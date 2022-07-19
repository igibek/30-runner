using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace GitHub.Runner.Worker {

    public class TaintVariable {
        public string Value { get; set; }
        public bool Tainted { get; set; }

        public TaintVariable(string value, bool tainted = false)
        {
            Value = value;
            Tainted = tainted;
        }
    }

    public interface ITaintContext
    {
        Dictionary<string, TaintVariable> T_EnvironmentVariables { get; }

        Dictionary<string, TaintVariable> T_Inputs { get; }

        Dictionary<string, TaintVariable> T_Outputs { get; }

        bool IsTainted(string value);
        // Concreate methods
        bool T_AddEnvironmentVariable(string name, string value) {
            return T_Add(name, value, T_EnvironmentVariables);
        }

        bool T_AddInput(string name, string value) {
            return T_Add(name, value, T_Inputs);
        }

        bool T_AddOutput(string name, string value) {
            return T_Add(name, value, T_Outputs);
        }

        bool T_Add(string name, string value, Dictionary<string, TaintVariable> targetDict) {
            var taintV = new TaintVariable(value);
            if (IsTainted(value)) {
                taintV.Tainted = true;
            }
            return targetDict.TryAdd(name, taintV);
        }

        TaintVariable GetInput(string name) {
            TaintVariable taintV;
            T_Inputs.TryGetValue(name, out taintV);
            return taintV;
        }
    }
}