from utils import call_chatgpt_fuzzer,fuzz_function

class InputMutatorAgent:
    def __init__(self, inputs, funname, code):
        self.inputs = inputs
        self.code = code
        self.funname = funname

    def mutate_inputs(self):
        # 返回 (变异后的输入, 扰动类型信息)
        mutated_inputs, mutation_meta = fuzz_function(self.inputs, self.code, self.funname)
        return mutated_inputs, mutation_meta
