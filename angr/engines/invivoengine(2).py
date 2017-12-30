import logging

from .engine import SimEngine
from .. import sim_options as o
l = logging.getLogger("angr.engines.hook")


# pylint: disable=abstract-method,unused-argument
class SimEngineInVivo(SimEngine):
    def __init__(self, project):
        super(SimEngineInVivo, self).__init__()
        self.project = project


    def _check(self, state, procedure=None, **kwargs):
        if o.INVIVO not in state.options:
            l.debug('Unicorn-engine is not enabled.')
            return False

        if self.project.loader._auto_load_libs == False or self.project._should_use_sim_procedures == False :
            return False

        libc_caller=[]
        # fisrt we create a cfg for get call_libc_func's address
        cfg = self.project.analyses.CFGAccurate(keep_state=True)
        callgraph = cfg.functions.callgraph

        libc_addr = []
        for libc_func in cfg.functions.values():
            libc_addr.append(libc_func.addr)
        for addr in libc_addr:
            caller = callgraph.predecessors(addr)
            for caller_addr in caller:
                libc_caller.append(caller_addr)




        # check If the func is a libc func
        if state.addr not in libc_caller:
            return False

        return True








    def process(self, state, **kwargs):
        # When reach libc_func's address,in-vivo engine's check will pass through and this process may begin!

        #we step the state up to the call_libc_func
        # get the lic_func's name and ret_addr
        '''
                Step 1,we creat a new angr project,in which set use_simprocedure=False because we are using in-vivo mode

                binary_path = state.project.filename
                self._project = angr.Project(binary_path,use_sim_procedures=False)
                Check first to make sure that execution has arrived at a certain libc_func's address!!!!!!
                '''
        libc_caller = []
        # fisrt we create a cfg for get call_libc_func's address
        cfg = self.project.analyses.CFGAccurate(keep_state=True)
        callgraph = cfg.functions.callgraph
        # next get the call_libc_func's addr
        libc_addr = []
        for libc_func in cfg.functions.values():
            libc_addr.append(libc_func.addr)
        for addr in libc_addr:
            caller = callgraph.predecessors(addr)
            for caller_addr in caller:
                libc_caller.append(caller_addr)
        index = libc_caller.index(state.addr)
        func_name = cfg.functions.values()[index].name
        all_func_name = []
        for func in cfg.functions.values:
            all_func_name.append(func.name)
        ret_addr = state.block().size + state.addr
        # get the libc_func state for unicorn_engine
        insts = len(state.block().instruction_addrs) - 1
        state.options.discard('INVIVO')
        succs = state.project.factory.successors(state, num_inst=insts).flat_successors
        state = succs[0]

        '''
        Step 2,we need to recognize all libc_func's address and its return address
        '''
        #we need to get all parameters in BVS
        if self.num_args is None:
            self.num_args = self._get_args_num(state)  # This function will be replaced by API provided by fish!!! hardcode now!!!
        # Second,phrase parameters
        if self.arguments is None:
            self._simcc = state.project.factory.cc
            sim_args = [self._simcc.arg(state, _) for _ in xrange(self.num_args)]
            self.arguments = sim_args
            # Third,we concrete all parameters
        for n in xrange(self.arguments):
            if self.arguments[n].symbolic:  # all parameters must be concrete!
                self.arguments[n] = state.se.solve(self.arguments[n])  # NOT SURE! CHECK IT!
                # Fourth,replace original parameters with concrete parameters


        self.project = state.project
        for obj in self.loader.initial_load_objects:
            libc_addr_dict = self._get_libc_addr(obj, state)

        libcaddr_retaddr = {}  # In this dict,key is libc_addr,valuse is the corresponding ret_addr
        for func_addr in libcaddr_retaddr.keys():
            ret_addr = self._libc_retaddr(func_addr)
            libcaddr_retaddr[func_addr] = ret_addr
        # later,we will pass those ret_addr in libcaddr_retaddr to unicorn as 'stop point'


        '''
        Step 3,generate a invivo_state which will be used by unicorn engine

        return invivo_state who has unicorn option
        '''
        invivo_state = state.copy()
        invivo_state.options |= so.unicorn  # add unicorn option to state option
        '''
        Step 4,concrete all the parameters of current function

        return invivo_state with concrete parameters
        '''
        # First we need to get all parameters in BVS
        sim_args = [inst.arg(_) for _ in xrange(inst.num_args)]

        # Second,we concrete all parameters

    def _get_args_num(self, state):
        '''
        FIX IT!
        This function is just for testing,because we are waitting fish!!!
        '''
        # Step 1:check the name of current function

        # Step 2:return corresponding args_num,each function has hardcoded args_num
        args_num = None
        if name not in libc_addr_dict.keys():  # we only process function in libc!!!
            raise Exception  # FIX IT!!!!!!!!!!!!!
        '''
        Generate reloc_AND_name to get the owner_name that will be used in follow code
        '''
        reloc_AND_name = {}  # value is reloc,key is the function's name,
        for obj in self.project.loader.initial_load_objects:
            for reloc in obj.imports.itervalues():
                reloc_AND_name[reloc.symbol.name] = reloc
        for libc_name in reloc_AND_name.keys():
            if name == libc_name:
                reloc = reloc_AND_name[libc_name]
        export = reloc.resolvedby
        owner_name = export.owner_obj.provides
        sim_lib = SIM_LIBRARIES[owner_name]
        if not sim_lib.has_implementation(export.name):
            raise Exception  # FIX IT
        simprocedure = sim_lib.get(name, self.project.arch)

        return simprocedure.num_args

    def _check_user_blacklists(self, f):
        """
        Has symbol name `f` been marked for exclusion by any of the user
        parameters?
        """
        blacklists = {}  # put the function name you don't want to concrete execute in there
        if f in blacklists:
            return True
        else:
            return False

    def _libc_retaddr(self, addr):
        '''
        Given a function's address,calculate its return address
        '''
        block = self.project.block(addr)
        ret_addr = block.addr + block.size
        return ret_addr

    #
    # Pickling
    #

    def __setstate__(self, state):
        super(SimEngineInVivo, self).__setstate__(state)
        self.project = state['project']

    def __getstate__(self):
        s = super(SimEngineInVivo, self).__getstate__()
        s['project'] = self.project
        return s



