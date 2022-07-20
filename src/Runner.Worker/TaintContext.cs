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

namespace GitHub.Runner.Worker {

    public class TaintContext : RunnerService
    {
        public TaintContext(Guid id, string displayName, IExecutionContext executionContext, bool isEmbedded = false)
        {
            Id = id;
            DisplayName = displayName;
            ExecutionContext = executionContext;
            IsEmbedded = isEmbedded;
            Inputs = new Dictionary<string, TaintVariable>();
            EnvironmentVariables = new Dictionary<string, TaintVariable>();
            Outputs = new Dictionary<string, TaintVariable>();

        }

        private static Dictionary<Guid, TaintContext> _cachedIds = new Dictionary<Guid, TaintContext>();

        public TaintContext(IExecutionContext executionContext) {
            ExecutionContext = executionContext;
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

        public bool IsEmbedded {get; private set; }
        
        public Dictionary<string, TaintVariable> EnvironmentVariables { get; private set; }

        public Dictionary<string, TaintVariable> Inputs { get; private set; }

        public Dictionary<string, TaintVariable> Outputs { get; private set; }

        private bool AddEnvironmentVariable(string key, string value)
        {
            var taintVariable = new TaintVariable(value, IsTainted(value));
            return EnvironmentVariables.TryAdd(key, taintVariable);
        }

        public void AddEnvironmentVariables(TemplateToken token)
        {
            string key = "";
            bool toogle = false;

            foreach (var env in token.Traverse())
            {    
                if (toogle) {
                    AddEnvironmentVariable(key, env.ToString());
                    toogle = false;
                } else {
                    toogle = true;
                    key = env.ToString();
                }
            }
        }

        // TODO: look for workflow syntax to make sure that we can not pass anything except string
        private bool AddInput(string key, string value)
        {
            
            //Trace.Info("Adding Tainted input into ...");
            var taintVariable = new TaintVariable(value, IsTainted(value));
            
            // adding input environment variable 
            // for every input runner will create env variable with "$INPUT_FOO" format
            // look AddInputsToEnvironment() function in Handler.cs
            string envKey = key.Replace(' ', '_').ToUpperInvariant();
            EnvironmentVariables.TryAdd(envKey, taintVariable);
            
            return Inputs.TryAdd(key, taintVariable);
        }

        public void AddInputs(TemplateToken token)
        {
            string key = "";
            bool isKey = true, skip = true;
            
            
            foreach (var input in token.Traverse()) {
                if (skip) {
                    skip = false;
                    continue;
                }

                if (isKey) {
                    isKey = false;
                    key = input.ToString();
                } else {
                    isKey = true;
                    AddInput(key, input.ToString());
                }
            }
        }

        public bool AddOutput(string key, string value)
        {
            var taintVariable = new TaintVariable(value, IsTainted(value));
            return Outputs.TryAdd(key, taintVariable);
        }

        public bool IsTainted(string value)
        {
            // TODO: how we can detect tainted input inside composite actions. IsTaintedInput? 
            return IsTaintedGithub(value) || IsTaintedStepOutput(value) || IsTaintedJobOutput(value) || IsTaintedEnvironment(value);
        }

        public bool IsTaintedEnvironment(string value)
        {
            // Used the regex from this thread: https://stackoverflow.com/questions/2821043/allowed-characters-in-linux-environment-variable-names
            Regex envRegex = new Regex(@"\$[a-z_][a-z0-9_]*", RegexOptions.Compiled);
            MatchCollection matchCollection = envRegex.Matches(value);
            TaintVariable taintVariable;
            foreach (var match in matchCollection)
            {
                var env = match.ToString();

                if (EnvironmentVariables.TryGetValue(env, out taintVariable)) {
                    if (taintVariable.Tainted) {
                        return true;
                    }
                } else if (Root != null) { 
                    var root = Root;
                    while (root != null) {
                        if (root.EnvironmentVariables.TryGetValue(env, out taintVariable)) {
                            if (taintVariable.Tainted) {
                                return true;
                            }
                        }
                        root = root.Root;
                    }
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
            return taintVariable.Tainted;
        }

        public bool IsTaintedStepOutput(string value)
        {
            // TODO: implement
            return false;
        }

        public async Task<int> ExecuteModule(TaintModule module) {
            string moduleName = String.Empty;
            if (module == TaintModule.Script) {
                moduleName = System.Environment.GetEnvironmentVariable("TAINT_BASH_MODULE") ?? "bash.py";
            } else if (module == TaintModule.NodeJS) {
                moduleName = System.Environment.GetEnvironmentVariable("TAINT_NODEJS_MODULE") ?? "nodejs.py";
            } else if (module == TaintModule.Composite) {
                moduleName = System.Environment.GetEnvironmentVariable("TAINT_BASH_MODULE") ?? "bash.py"; // FIX:
            } else if (module == TaintModule.Docker) {
                moduleName = System.Environment.GetEnvironmentVariable("TAINT_BASH_MODULE") ?? "bash.py"; // FIX:
            }
            var _invoker = HostContext.CreateService<IProcessInvoker>();
            string inputs = StringUtil.ConvertToJson(Inputs); // convert object into string
            string arguments = String.Format("--inputs={0} --envs={1}", inputs, StringUtil.ConvertToJson(EnvironmentVariables));
            string workingDirectory = "/";
            var environments = new Dictionary<string, string>();
        
            return await _invoker.ExecuteAsync(workingDirectory, moduleName, arguments,  environments, ExecutionContext.CancellationToken);
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

    }

    public enum TaintModule {
        NodeJS,
        Script,
        Docker,
        Composite
    }

    public class TaintVariable {
        public string Value { get; set; }
        public bool Tainted { get; set; }

        public TaintVariable(string value, bool tainted = false)
        {
            Value = value;
            Tainted = tainted;
        }
    }
}