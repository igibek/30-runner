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

namespace GitHub.Runner.Worker {

    public class TaintContext : RunnerService
    {

        

        public TaintContext(IExecutionContext executionContext, TaintContext parent = null) {
            ExecutionContext = executionContext;
            _parentTaintContext = parent;
            Inputs = new Dictionary<string, TaintVariable>();
            EnvironmentVariables = new Dictionary<string, TaintVariable>();
            // Outputs = new Dictionary<string, TaintVariable>();
            // Files = new HashSet<string>();
            // Secrets = new Dictionary<string, string>();
        }

        public Guid Id { get; private set; }
        public string DisplayName { get; private set; }
        
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
        private static Dictionary<Guid, TaintContext> _cachedIds = new Dictionary<Guid, TaintContext>();
        public static string RootDirectory {get; private set; }
        public static string ModuleDirectory {get; private set; }
        public static string TaintDirectory {get; private set; } = "_taint";
        public static string RepositoryDirectory {get; private set; } = string.Empty;

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

            // Only job context should have Outputs, Files, Secrets
            Outputs = new Dictionary<string, TaintVariable>();
            Files = new HashSet<string>();
            Secrets = new Dictionary<string, string>();
        }

        public bool IsEmbedded {get; private set; }
        public bool DependOnSecret { get; private set; } = false;
        public Dictionary<string, TaintVariable> EnvironmentVariables { get; private set; }

        public Dictionary<string, TaintVariable> Inputs { get; private set; }
        public HashSet<string> Values {get; private set; }

        public Dictionary<string, TaintVariable> Outputs { get; private set; }
        public HashSet<string> Files {get; private set; }
        public Dictionary<string, string> Secrets {get; private set; }
        public ActionExecutionType ExecutionType {get; set; }

        
        

        public void AddEnvironmentVariables(TemplateToken token)
        {
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
            var taintVariable = new TaintVariable(value, IsTainted(value));
            return EnvironmentVariables.TryAdd(key, taintVariable);
        }

        public void AddInputs(TemplateToken token)
        {
            if (token == null) return;
            
            // TODO: are you sure that this is MappingToken
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
            
            Trace.Info("TAINTED: Adding input key-value. Key: {0}, Value: {1}", key, value);
            bool tainted = IsTainted(value);
            bool secret = IsSecret(value);
            if (secret) DependOnSecret = true;

            
            
            var taintVariable = new TaintVariable(value, tainted, secret);
            
            // adding input environment variable 
            // for every input runner will create env variable with "$INPUT_FOO" format
            // look AddInputsToEnvironment() function in Handler.cs
            string envKey = key.Replace(' ', '_').ToUpperInvariant();
            EnvironmentVariables.TryAdd(envKey, taintVariable);
            
            return Inputs.TryAdd(key, taintVariable);
        }

        
        public void AddOutputs(TemplateToken token) {
            
            var mapping = token.AssertMapping("taint outputs");

            foreach (var pair in mapping) {
                string key = pair.Key.ToString();
                string value = pair.Value.ToString();
                AddOutput(key, value);
            }
        }

        public bool AddOutput(string key, string value)
        {
            var taintVariable = new TaintVariable(value, IsTainted(value));
            return Outputs.TryAdd(key, taintVariable);
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
            return IsTaintedGithub(value) || IsTaintedStepOutput(value) || IsTaintedJobOutput(value) || IsTaintedEnvironment(value);
        }

        public bool IsTaintedEnvironment(string value)
        {
            // Used the regex from this thread: https://stackoverflow.com/questions/2821043/allowed-characters-in-linux-environment-variable-names
            // TODO: what about environment variables in Windows
            Regex envRegex = new Regex(@"\$[a-z_][a-z0-9_]*", RegexOptions.Compiled);
            MatchCollection matchCollection = envRegex.Matches(value);
            TaintVariable taintVariable;
            foreach (var match in matchCollection)
            {
                var env = match.ToString();

                var current = this;
                while (current != null) {
                    if (current.EnvironmentVariables.TryGetValue(env, out taintVariable)) {
                        if (taintVariable.Tainted) {
                            return true;
                        }
                    }
                    current = current._parentTaintContext;    
                }
            }

            return false;
        }

        public bool IsTaintedGithub(string value)
        {
            // get the list of tainted inputs from here: https://securitylab.github.com/research/github-actions-untrusted-input/ 
            string[] regexPatterns = { @"github\.event\.inputs\.[a-z0-9_-]+", // event inputs
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
            // TODO: implement. 
            string [] regexPatterns = { @"github\.inputs.\[a-z0-9_-]+" };

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

        public bool IsTaintedJobOutput(string reference)
        {
            // root TaintContext belongs to Job
            Root.Outputs.TryGetValue(reference, out TaintVariable taintVariable);
            
            // checks if taintVariable is null, otherwise it will throw null pointer exception
            return taintVariable == null ? false : taintVariable.Tainted;
        }

        public bool IsTaintedStepOutput(string value)
        {
            // TODO: implement
            return false;
        }

        public async Task<int> ExecuteModule(ActionExecutionType executionType, string path) {
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
                if (DependOnSecret && !string.IsNullOrEmpty(path)) {
                    Files.Add(path);
                }
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

            
            string contents = StringUtil.ConvertToJson(new {
                Type = executionType.ToString(),
                Action = ExecutionContext.GetGitHubContext("action_repository"),
                Reference = ExecutionContext.GetGitHubContext("action_ref"),
                Path = path,
                Inputs = Inputs,
                Environments = EnvironmentVariables,
                Files = Files,
                Values = new List<string>() // values that are considered tainted
            });
            string fileName = String.Format("{0}-{1}-{2}.json", ExecutionContext.GetGitHubContext("run_id"), ExecutionContext.GetGitHubContext("job"), ExecutionContext.Id.ToString());
            string filePath = Path.Combine(TaintContext.RepositoryDirectory, fileName);

            File.WriteAllText(filePath, contents);

            string arguments = String.Format("--path={0}", filePath);

            var environments = new Dictionary<string, string>();

            var _invoker = HostContext.CreateService<IProcessInvoker>();
            _invoker.OutputDataReceived += OnDataReceived;
            _invoker.ErrorDataReceived += OnErrorReceived;

            return await _invoker.ExecuteAsync("", Path.Combine(TaintContext.ModuleDirectory, moduleName), arguments,  environments, ExecutionContext.CancellationToken);
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
}