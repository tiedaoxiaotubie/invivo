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
        '''
        Step 1,we creat a new angr project,in which set use_simprocedure=False because we are using in-vivo mode

        binary_path = state.project.filename
        self._project = angr.Project(binary_path,use_sim_procedures=False)
        Check first to make sure that execution has arrived at a certain libc_func's address!!!!!!
        '''
        #we step the state up to the call_libc_func
        insts = len(state.block().instruction_addrs) - 1
        state.options.discard('INVIVO')
        succs = state.project.factory.successors(state, num_inst=insts).flat_successors
        state = succs[0]

        #get the lic_func's name and ret_addr
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
        index = libc_caller[state.addr]

        func_name = cfg.functions.values()[index].name
        ret_addr = state.block().size + state.addr

        '''
        Step 2,we need to recognize all libc_func's address and its return address
        '''



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

    def _get_libc_addr(self):
        """
        This scans through an objects imports and hooks them with simprocedures from our library whenever possible
        """
        libc_addr_dict = {}  # value is function's name,key is the address of function
        for obj in self.project.loader.initial_load_objects:
         for reloc in obj.imports.itervalues():
            # Step 2.1: Quick filter on symbols we really don't care about
            libc_addr_dict[reloc.symbol.name] = reloc.addr
        return libc_addr_dict

    def _get_args_num(self, state):
        '''
        FIX IT!
        This function is just for testing,because we are waitting fish!!!
        '''
        # Step 1:check the name of current function
        libc_addr = {}
        libc_addr = self._get_libc_addr()
        index = libc_addr.values().index(state.addr)
        return libc_addr.keys()[index]

        #func_name
        # Step 2:return corresponding args_num,each function has hardcoded args_num
        args_num = None
        if name == 'libc_start_main':
            args_num = 5
            return args_num
        elif name == 'read':
            args_num = 3
        if args_num is None:
            raise Exception  # correct it!
        return args_num

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



