using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using GitHub.DistributedTask.ObjectTemplating.Tokens;
using System.Threading.Tasks;
using GitHub.Runner.Worker.Handlers;
using System.Diagnostics;
using System.IO;
using GitHub.Runner.Sdk;
using GitHub.Runner.Common;
using GitHub.DistributedTask.Pipelines.ObjectTemplating;
using GitHub.DistributedTask.Pipelines;
using Newtonsoft.Json;
using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.FileSystemGlobbing.Abstractions;

namespace GitHub.Runner.Worker {

    public class TaintFileName {
        // step__{run_id}__{workflow}__{job}__{context_name}__inputs.json
        public static readonly string StepInputFileName = "step::{0}::{1}::{2}::{3}::inputs.json";
        // step__{run_id}__{workflow}__{job}__{context_name}__outputs.json
        public static readonly string StepOutputFileName = "step::{0}::{1}::{2}::{3}::outputs.json";
        // job__{run_id}__{workflow}__{job}.json
        public static readonly string JobOutputFileName = "job::{0}::{1}::{2}.json";

        public static string GenerateStepInputFilename(string runnerId, string workflow, string jobName, string contextName, string scopeName = null) {
            if (String.IsNullOrEmpty(scopeName)) {
                return String.Format(TaintFileName.StepInputFileName, runnerId, workflow, jobName, contextName);
            }
            return String.Format(TaintFileName.StepInputFileName, runnerId, workflow, jobName, contextName + "__" + scopeName);
        }

        public static string GenerateStepOutputFilename(string runnerId, string workflow, string jobName, string contextName, string scopeName = null) {
            if (String.IsNullOrEmpty(scopeName)) {
                return String.Format(TaintFileName.StepOutputFileName, runnerId, workflow, jobName, contextName);
            }
            return String.Format(TaintFileName.StepOutputFileName, runnerId, workflow, jobName, contextName + "__" + scopeName);
        }

        public static string GenerateJobFilename(string runnerId, string workflow, string jobName) {
            return String.Format(TaintFileName.JobOutputFileName, runnerId, workflow, jobName);
        }
    }
    public class TaintContext : RunnerService
    {

        public TaintContext(IExecutionContext executionContext, TaintContext parent = null) {
            ExecutionContext = executionContext;
            _parentTaintContext = parent;
            Inputs = new Dictionary<string, TaintVariable>();
            EnvironmentVariables = new Dictionary<string, TaintVariable>();
            IsEmbedded = ExecutionContext.IsEmbedded;
        }

        public Guid Id { get; private set; }
        
        public IExecutionContext ExecutionContext { get; set; }

        private TaintContext _parentTaintContext = null;

        public TaintContext Root 
        { 
            get {
                var result = this;

                while (result._parentTaintContext != null) {
                    result = result._parentTaintContext;
                }

                return result;
            }
        }
        
        /**
        STATIC SHARED VARIABLES
        */
        public static string EventName { get; private set; }
        public static string RootDirectory {get; private set; }
        public static string ModuleDirectory {get; private set; }
        public static string TaintDirectory {get; private set; } = "_taint";
        public static string RepositoryDirectory {get; private set; } = string.Empty;
        public static TaintEvent Event {get; private set; } = null;
        public static string WorkflowFilePath { get; private set; }
        public static string JobName { get; private set; }

        

        public bool IsEmbedded {get; private set; }
        public bool DependOnSecret { get; private set; } = false;
        public Dictionary<string, TaintVariable> EnvironmentVariables { get; private set; }
        public Dictionary<string, TaintVariable> Inputs { get; private set; }

        /**
        GLOBAL SHARED VALUES
        */
        public HashSet<string> Values {get; private set; }
        public HashSet<string> Files {get; private set; }
        public Dictionary<string, string> Secrets {get; private set; }
        public Dictionary<string, TaintVariable> StepOutputs { get; private set; }
        public Dictionary<string, TaintVariable> JobOutputs {get; private set; }
        public Dictionary<string, TaintVariable> Artifacts { get; private set; }
        public Dictionary<string, TaintVariable> PreviousJobs {get; private set; }

        // This method called only once during job initialization
        // inside ExecutionContext.InitializeJob method
        public void InitialSetup(IHostContext hostContext) 
        {
            base.Initialize(hostContext);
            
            RootDirectory = Path.Combine(HostContext.GetDirectory(WellKnownDirectory.Root), TaintDirectory);
            if (!Directory.Exists(RootDirectory)) {
                Directory.CreateDirectory(RootDirectory);        
            }
            ModuleDirectory = Path.Combine(RootDirectory, "modules");
            RepositoryDirectory = Path.Combine(RootDirectory, ExecutionContext.GetGitHubContext("repository"));
            // EventName = ExecutionContext.GetGitHubContext("event_name");

            // Only job context should have Outputs, Files, Secrets
            StepOutputs = new Dictionary<string, TaintVariable>();
            JobOutputs = new Dictionary<string, TaintVariable>();
            Artifacts = new Dictionary<string, TaintVariable>();
            Files = new HashSet<string>();
            Secrets = new Dictionary<string, string>();
            Values = new HashSet<string>();
            PreviousJobs = new Dictionary<string, TaintVariable>();
            WorkflowFilePath = ExecutionContext.Global.Variables.Get("system.workflowFilePath");
            JobName = ExecutionContext.Global.Variables.Get("system.github.job");
        }

        public void AddEnvironmentVariables(TemplateToken token)
        {
            Trace.Info("Adding environment variables");
            if (token == null) return;

            var mapping = token.AssertMapping("taint envs");

            foreach (var pair in mapping) {
                string key = pair.Key.ToString();
                string value = pair.Value.ToString();
                AddEnvironmentVariable(key, value);
            }
        }

        private bool AddEnvironmentVariable(string key, string value)
        {
            Trace.Info($"Adding env key-value. Key: {key}, Value: {value}");
            bool tainted = IsTainted(value);
            bool issecret = IsSecret(value);
            var taintVariable = new TaintVariable(value, tainted, issecret);
            return EnvironmentVariables.TryAdd(key, taintVariable);
        }

        public void AddInputs(TemplateToken token)
        {
            Trace.Info("Adding inputs");
            if (token == null) return;
            var mapping = token.AssertMapping("taint inputs");
            foreach (var pair in mapping) {
                // TODO: type of the key and value
                string key = pair.Key.ToString();
                string value = pair.Value.ToString();
                AddInput(key, value);
            }
        }

        private bool AddInput(string key, string value)
        {
            
            Trace.Info($"Adding input key-value. Key: {key}, Value: {value}");
            bool tainted = IsTainted(value);
            bool secret = IsSecret(value);
            if (secret) {
                DependOnSecret = true;
                // TODO: get the secret name
                // TBH I do NOT know why I added it here.
                // Currently we can get the all the secrets from inputs.
                Root.Secrets.TryAdd(key, value);
            }
   
            var taintVariable = new TaintVariable(value, tainted, secret);
            
            // adding input environment variable 
            // for every input runner will create env variable with "$INPUT_FOO" format
            // look AddInputsToEnvironment() function in Handler.cs
            string envKey = "INPUT_" + key.Replace(' ', '_').ToUpperInvariant();
            EnvironmentVariables.TryAdd(envKey, taintVariable);
            
            // We are using TryAdd instead of indexing because we avoid overwriting existing values.
            // For example in the case when we are evaluating the Actions default value
            return Inputs.TryAdd(key, taintVariable);
        }

        public void AddEvaluatedInputs(Dictionary<string, string> inputs) {
            foreach (var input in inputs) {
                if (Inputs.TryGetValue(input.Key, out TaintVariable variable)) {
                    Inputs[input.Key].EvaluatedValue = input.Value;
                    if (variable.Tainted) {
                        Trace.Info($"Adding evaluated input key-value. Key: {input.Key}, Value: {input.Value}");
                        Root.Values.Add(input.Value);
                    }
                }    
            }
        }

        public void AddEvaluatedEnvironments(Dictionary<string, string> environments) {
            foreach (var env in environments) {
                if (EnvironmentVariables.TryGetValue(env.Key, out TaintVariable variable)) {
                    EnvironmentVariables[env.Key].EvaluatedValue = env.Value;
                    if (variable.Tainted) {
                        Trace.Info($"Adding evaluated env key-value. Key: {env.Key}, Value: {env.Value}");
                        Root.Values.Add(env.Value);
                    }
                }
            }
        }

        public void AddEvaluatedJobOutputs(Dictionary<string, string> outputs) {
            foreach (var output in outputs) {
                if (Root.JobOutputs.TryGetValue(output.Key, out TaintVariable variable)) {
                    Root.JobOutputs[output.Key].EvaluatedValue = output.Value;
                    if (variable.Tainted) {
                        Trace.Info($"Adding job output key-value. Key: {output.Key}, Value: {output.Value}");
                        Root.Values.Add(output.Value);
                    }
                }
            }
        }

        public bool UpdateJobOutputsWithValue(string key, string value) {
            if (Root.JobOutputs.TryGetValue(key, out TaintVariable variable)) {
                Root.JobOutputs[key].EvaluatedValue = value;
                if (variable.Tainted) {
                    Root.Values.Add(value);
                }
                return true;
            }
            return false;
        }

        public bool UpdateStepOutputsWithValue(string key, string value) {
            if (Root.StepOutputs.TryGetValue(key, out TaintVariable variable)) {
                Root.StepOutputs[key].EvaluatedValue = value;
                if (variable.Tainted) {
                    Root.Values.Add(value);
                }
                return true;
            }
            return false;
        }

        public void AddJobOutputs(TemplateToken token) {
            var mapping = token.AssertMapping("taint job outputs");

            foreach (var pair in mapping) {
                string key = pair.Key.ToString();
                string value = pair.Value.ToString();
                var taintVariable = new TaintVariable(value, IsTainted(value), IsSecret(value));
                Root.JobOutputs.TryAdd(key, taintVariable);
            }
        }

        public void AddStepOutputs(TemplateToken token) {
            
            var mapping = token.AssertMapping("taint step outputs");

            foreach (var pair in mapping) {
                string key = pair.Key.ToString();
                string value = pair.Value.ToString();
                var taintVariable = new TaintVariable(key, IsTainted(value), IsSecret(value));
                Root.StepOutputs.TryAdd(key, taintVariable);
            }
        }

        public bool IsSecret(string value) {
            string [] regexPatterns = { @"github\.token", @"secrets\.[a-zA-z0-9]+" };

            foreach (string pattern in regexPatterns) {
                MatchCollection matches = Regex.Matches(value, pattern, RegexOptions.IgnoreCase);
                if (matches.Count > 0) {
                    return true;
                }
            }
            return false;
        }
        public bool IsTainted(string value)
        {
            // TODO: how we can detect tainted input inside composite actions. IsTaintedInput? 
            return IsTaintedGithub(value)|| IsTaintedEnvironment(value) || IsTaintedStepOutput(value) || IsTaintedJobOutput(value);
        }

        public bool IsTaintedEnvironment(string value)
        {
            // Used the regex from this thread: https://stackoverflow.com/questions/2821043/allowed-characters-in-linux-environment-variable-names
            // NOTE: what about environment variables in Windows
            string [] regexPatterns = {@"\$[a-zA-Z_][a-zA-Z0-9_]*", @"env\.[a-zA-Z0-9_-]+"};
            TaintVariable taintVariable;
            bool isTainted = false;
            foreach (var regex in regexPatterns) {
                Regex envRegex = new Regex(regex, RegexOptions.Compiled);
                MatchCollection matchCollection = envRegex.Matches(value);    
                foreach (var match in matchCollection)
                {
                    var env = match.ToString(); // NOTE: returns env.FOO -> need to get FOO
                    env = env.Replace("env.", "");
                    env = env.Replace("$", "");

                    var current = this;
                    while (current != null) {
                        if (current.EnvironmentVariables.TryGetValue(env, out taintVariable)) {
                            isTainted = taintVariable.Tainted;
                            break;
                        }
                        current = current._parentTaintContext; // NOTE: Should we take parent on only Job is enough. Test it on composite actions
                    }
                }
            }
            

            return isTainted;
        }

        public bool IsTaintedGithub(string value)
        {
            // get the list of tainted inputs from here: https://securitylab.github.com/research/github-actions-untrusted-input/ 
            string[] regexPatterns = { @"github\.event\.inputs\.[a-z0-9_-]+", // event inputs NOTE: can inputs use CAPITAL letters?
                                        @"github\.event\.issue\.title", @"github\.event\.issue\.body", // issues 
                                        @"github\.event\.pull_request\.title", @"github\.event\.pull_request\.body", // pull requests
                                        @"github\.event\.pull_request\.head\.ref", @"github\.event\.pull_request\.head\.label", @"github\.event\.pull_request\.head\.repo\.default_branch",// pull requests
                                        @"github\.event\.comment\.body", @"github\.event\.review\.body", @"github\.event\.review_comment\.body", // reviews and comment
                                        @"github\.event\.pages\.[-_a-z0-9]+\.page_name", 
                                        @"github.event.head_commit.message", @"github\.event\.head_commit\.author\.email", @"github\.event\.head_commit\.author\.name", // head_commit
                                        @"github\.event\.commits\.[a-z0-9_-]+\.author\.email", @"github\.event\.commits\.[a-z0-9_-]+\.author\.name", @"github\.event\.commits\.[a-z0-9_-]+\.message", // commits
                                        @"github\.head_ref", // head_ref
                                        };
            foreach (string pattern in regexPatterns) {
                MatchCollection matches = Regex.Matches(value, pattern, RegexOptions.IgnoreCase);
                if (matches.Count > 0) {
                    return true;
                }
            }
            
            return false;
        }

        public bool IsTaintedInput(string value)
        {
            string [] regexPatterns = { @"github\.inputs.\[a-zA-Z0-9_-]+" };

            foreach (string pattern in regexPatterns) {
                MatchCollection matches = Regex.Matches(value, pattern, RegexOptions.IgnoreCase);
                // TODO: get the input name
                string input = "";
                TaintVariable taintVariable = null;
                if (Inputs.TryGetValue(input, out taintVariable)) {
                    if (taintVariable.Tainted) {
                        return true;
                    }
                }
            }
            return false;
        }

        public bool IsTaintedJobOutput(string value)
        {
            // TODO: reusable workflow uses different contexts jobs.<id>.outputs.<name>
            string regexPattern = @"needs\.[a-zA-Z0-9]+\.outputs\.[a-zA-Z0-9]+";
            Regex regex = new Regex(regexPattern, RegexOptions.Compiled);
            MatchCollection matches = regex.Matches(value);
            foreach(var match in matches) {
                string reference = match.ToString();
                reference = reference.Replace("needs.", "").Replace("outputs.", "");
                // root TaintContext belongs to Job
                if (Root.PreviousJobs.TryGetValue(reference, out TaintVariable taintVariable)) {
                    if (taintVariable.Tainted) {
                        return true;
                    }
                }
            }
            
            return false;
        }

        public bool IsTaintedStepOutput(string value) {
            // TODO: implement step output for non conventional step output form
            // "steps['{stepName}']['outputs']['{outputName}']"
            
            string regexPattern = @"steps.\[a-zA-Z0-9]+\.outputs\.[a-zA-Z_][a-zA-Z0-9_]*";
            Regex regex = new Regex(regexPattern, RegexOptions.Compiled);
            MatchCollection matchCollection = regex.Matches(value);
            foreach (var match in matchCollection) {
                string reference = match.ToString();
                var parts = reference.Split(".");
                
                if (parts.Length != 4) {
                    continue;
                }

                reference = $"{parts[1]}.{parts[3]}";

                if (Root.StepOutputs.TryGetValue(reference, out TaintVariable taintVariable)) {
                    if (taintVariable.Tainted) {
                        return true;
                    }
                }
                
            }
            return false;
        }

        public void CheckArtifact() {
            
            string action_ref = ExecutionContext.GetGitHubContext("action_repository");

            // verify that this is called only for actions/upload-artifacts
            if (action_ref != "actions/upload-artifacts" || action_ref != "actions/download-artifacts") {
                return;
            }
            // iterate through the actions/upload-artifacts inputs 
            // checks it agains global files field
            if (Inputs.TryGetValue("path", out TaintVariable taintVariable)) {
                string artifactName = Inputs["name"].EvaluatedValue;
                string artifactPath = taintVariable.EvaluatedValue;
                
                // checks if the path is marked as tainted
                // TODO: is method does not consider several edge cases
                // 1. When the PATH is array (done)
                // 2. When the PATH is glob
                // 3. When artifact is under the tainted folder. (done)
                // aritfactPath input can include array of different locations
                string[] artifacts = artifactPath.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var artifact in artifacts) {
                    if (Files.Contains(artifact)) {
                        Root.Artifacts.TryAdd(artifactPath, new TaintVariable(artifactPath, true));
                    } else {
                        foreach (var file in Files) {
                            if (file.StartsWith(artifact)) {
                                Root.Artifacts.TryAdd(artifactPath, new TaintVariable(artifactPath, true));
                            }
                        }
                    }
                }
            }
            
        }
        public async Task<int> ExecuteModule(ActionExecutionType executionType, string path) {
            
            if (executionType == ActionExecutionType.Script && DependOnSecret && !string.IsNullOrEmpty(path)) {
                Root.Files.Add(path);
            }
            
            var inputs = new Dictionary<string, TaintVariable>();
            foreach(var item in Inputs) {
                if (item.Value.Tainted || item.Value.Secret) {
                    inputs.Add(item.Key, item.Value);
                }
            }

            var env = new Dictionary<string, TaintVariable>();
            foreach (var item in EnvironmentVariables) {
                if (item.Value.Tainted || item.Value.Secret) {
                    env.Add(item.Key, item.Value);
                }
            }
            this.CheckArtifact();
            string contents = StringUtil.ConvertToJson(new {
                Type = executionType.ToString(),
                Action = ExecutionContext.GetGitHubContext("action_repository"),
                Reference = ExecutionContext.GetGitHubContext("action_ref"),
                Path = path,
                Inputs = inputs,
                Environments = env,
                Files = Root.Files,
                Values = Root.Values, // values that are considered tainted
                Secrets = Root.Secrets // all secrets values
            });

            string moduleName = GetModuleName(executionType);
            string workflow = Path.GetFileNameWithoutExtension(WorkflowFilePath);

            string inputFileName = TaintFileName.GenerateStepInputFilename(ExecutionContext.GetGitHubContext("run_id"), workflow, ExecutionContext.GetGitHubContext("job"), ExecutionContext.ContextName, ExecutionContext.ScopeName);
            string outputFileName = TaintFileName.GenerateStepOutputFilename(ExecutionContext.GetGitHubContext("run_id"), workflow, ExecutionContext.GetGitHubContext("job"), ExecutionContext.ContextName, ExecutionContext.ScopeName);

            string inputFilePath = Path.Combine(TaintContext.RepositoryDirectory, inputFileName);
            string outputFilePath = Path.Combine(TaintContext.RepositoryDirectory, outputFileName);

            File.WriteAllText(inputFilePath, contents);

            string arguments = String.Format("--input={0} --output={1}", inputFilePath, outputFilePath);

            var environments = new Dictionary<string, string>();

            var _invoker = HostContext.CreateService<IProcessInvoker>();
            _invoker.OutputDataReceived += OnDataReceived;
            _invoker.ErrorDataReceived += OnErrorReceived;
            
            
            return await _invoker.ExecuteAsync("", Path.Combine(TaintContext.ModuleDirectory, moduleName), arguments,  environments, ExecutionContext.CancellationToken);
        }

        public void SaveJobTaintContext() {
            
            var outputs = new Dictionary<string, TaintVariable>();
            foreach (var item in Root.JobOutputs) {
                if (item.Value.Tainted || item.Value.Secret) {
                    outputs.Add(item.Key, item.Value);
                }
            }

            var artifacts = new Dictionary<string, TaintVariable>();
            foreach (var item in Root.Artifacts) {
                artifacts.Add(item.Key, item.Value);
            }

            string content = StringUtil.ConvertToJson(new JobTaintContext{
                JobName = ExecutionContext.GetGitHubContext("job"),
                JobOutputs = outputs,
                Artifacts = artifacts
            });
            string workflow = Path.GetFileNameWithoutExtension(WorkflowFilePath);
            string fileName = TaintFileName.GenerateJobFilename(ExecutionContext.GetGitHubContext("run_id"), workflow, ExecutionContext.GetGitHubContext("job"));
            string filePath = Path.Combine(TaintContext.RepositoryDirectory, fileName);
            File.WriteAllText(filePath, content);
        }

        public void RestoreJobTaintContext() {
            Matcher matcher = new();
            string jobGlob = TaintFileName.GenerateJobFilename(ExecutionContext.GetGitHubContext("run_id"), Path.GetFileNameWithoutExtension(WorkflowFilePath),"*");
            matcher.AddInclude(jobGlob);
            try {
                var files = matcher.GetResultsInFullPath(TaintContext.RepositoryDirectory);
                PatternMatchingResult result = matcher.Execute(new DirectoryInfoWrapper(new DirectoryInfo(TaintContext.RepositoryDirectory)));
                if (result.HasMatches) {
                    foreach (var file in files) {
                        string content = File.ReadAllText(file);
                        var jobTaintContext = JsonConvert.DeserializeObject<JobTaintContext>(content);
                        foreach (var jobOutput in jobTaintContext.JobOutputs) {
                            Root.PreviousJobs.Add($"{jobTaintContext.JobName}.${jobOutput.Key}", jobOutput.Value);
                            // adding evaluated values to the global values
                            Root.Values.Add(jobOutput.Value.EvaluatedValue);
                        }
                        foreach (var artifact in jobTaintContext.Artifacts) {
                            /* TODO: need to store the artifacts from previous jobs in separate property
                             * because it is possible to overwrite the existing artifacts
                             */
                            Root.Artifacts.Add(artifact.Key, artifact.Value);
                        }
                    }
                }
            } catch (Exception ex) {
                throw new Exception(ex.Message);
            }
        }

        // bind the secret with specific action? But how?
        public void TrackSecret(string path) {
            using var watcher = new FileSystemWatcher(path);

            watcher.NotifyFilter = NotifyFilters.Attributes
                                 | NotifyFilters.CreationTime
                                 | NotifyFilters.DirectoryName
                                 | NotifyFilters.FileName
                                 | NotifyFilters.LastAccess
                                 | NotifyFilters.LastWrite
                                 | NotifyFilters.Security
                                 | NotifyFilters.Size;

            watcher.Changed += OnChanged;
            watcher.Created += OnCreated;
            watcher.Deleted += OnDeleted;
            watcher.Renamed += OnRenamed;
            watcher.Error += OnError;

            watcher.Filter = "*.sh";
            watcher.IncludeSubdirectories = true;
            watcher.EnableRaisingEvents = true;

            // Console.WriteLine("Press enter to exit.");
            // Console.ReadLine();
        }

        private void OnChanged(object sender, FileSystemEventArgs e)
        {
            if (e.ChangeType != WatcherChangeTypes.Changed)
            {
                return;
            }
            ExecutionContext.Output($"Changed: {e.FullPath} Changed by {Id}");
        }

        private void OnCreated(object sender, FileSystemEventArgs e)
        {
            string value = $"Created: {e.FullPath} Changed by {Id}";
            ExecutionContext.Output(value);
        }

        private void OnDeleted(object sender, FileSystemEventArgs e) =>
            ExecutionContext.Output($"Deleted: {e.FullPath} Changed by {Id}");

        private void OnRenamed(object sender, RenamedEventArgs e)
        {
            ExecutionContext.Output($"Renamed:");
            ExecutionContext.Output($"    Old: {e.OldFullPath} Changed by {Id}");
            ExecutionContext.Output($"    New: {e.FullPath} Changed by {Id}");
        }

        private void OnError(object sender, ErrorEventArgs e) =>
            PrintException(e.GetException());

        #nullable enable
        private void PrintException(Exception? ex)
        {
            if (ex != null)
            {
                ExecutionContext.Output($"Message: {ex.Message}");
                ExecutionContext.Output("Stack//Trace:");
                ExecutionContext.Output(ex.StackTrace);
                PrintException(ex.InnerException);
            }
        }
        #nullable disable
        public void OnDataReceived(object sender, ProcessDataReceivedEventArgs e) {
            var line = e.Data;
            ExecutionContext.Output(line);
        }

        public void OnErrorReceived(object sendder, ProcessDataReceivedEventArgs e) {
            var line = e.Data;
            ExecutionContext.Error(line);
        }

        /***/
        private string GetModuleName(ActionExecutionType executionType) {
            string moduleName = String.Empty;
            
            if (string.IsNullOrEmpty(RepositoryDirectory)) {
                RepositoryDirectory = Path.Combine(RootDirectory, ExecutionContext.GetGitHubContext("repository"));
                if (!Directory.Exists(RepositoryDirectory)) {
                    Directory.CreateDirectory(RepositoryDirectory);
                }
            }

            if (executionType == ActionExecutionType.Script) {
                string shell = "sh";
                if (Inputs.TryGetValue("shell", out TaintVariable variable)) {
                    shell = variable.EvaluatedValue;
                } else if (string.IsNullOrEmpty(ExecutionContext.ScopeName) && ExecutionContext.Global.JobDefaults.TryGetValue("run", out var runDefaults)) {
                    runDefaults.TryGetValue("shell", out shell);
                }

                moduleName = System.Environment.GetEnvironmentVariable($"TAINT_{shell.ToUpper()}_MODULE") ?? "./script.py";
            } else if (executionType == ActionExecutionType.NodeJS) {
                moduleName = System.Environment.GetEnvironmentVariable("TAINT_NODEJS_MODULE") ?? "./nodejs.py";
            } else if (executionType == ActionExecutionType.Composite) {
                // NOTE: not clear what to do with that. 
                // Probably just ignore because composite actions are consists of different actions and script.
                // NodeJS and Script will be taint tracked recursively from Composite actions
            } else if (executionType == ActionExecutionType.Container) {
                // ActionExecutionType.Container is not supported at this stage
            } else if (executionType == ActionExecutionType.Plugin) {
                // ActionExecutionType.Plugin is not supported at this stage
            }

            return moduleName;
        }

    }

    public enum TaintModule {
        NodeJS,
        Script,
        Docker,
        Composite
    }

    public class TaintVariable {
        // NOTE: should distinguish between expression and value
        public string Name { get; set; }
        public string Value { get; set; }
        public string EvaluatedValue { get; set; }
        public bool Tainted { get; set; }
        public bool Secret { get; set; }
        public TaintVariable(string value, bool tainted = false, bool secret = false)
        {
            Value = value;
            Tainted = tainted;
            Secret = secret;
            EvaluatedValue = "";
        }
    }

    public class TaintFile {
        public string Path { get; set; }
        public bool Tainted { get; set; }
        public bool Secret { get; set; }
        public bool Directory { get; set; }
    }

    public class TaintEvent {
        public string Workflow { get; set; }
    }

    public class JobTaintContext {
        public string JobName {get; set; }
        public Dictionary<string, TaintVariable> Artifacts {get; set; }
        public Dictionary<string, TaintVariable> JobOutputs {get; set; }

    }
}