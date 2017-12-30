import logging
from .. import sim_options as o
from .engine import SimEngine
import angr
import nose
#from ..procedures.definitions import SIM_LIBRARIES
l = logging.getLogger("angr.engines.invivo")


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
    
    def process(self, state,  **kwargs):
        #When reach libc_func's address,in-vivo engine's check will pass through and this process may begin!
       
        '''
        Step 1,we need to recognize all libc_func's address and its return address
        '''
        self.arguments = None #arguments of the function to be concrete executed
        self.num_args = None #The number of arguments
        self._simcc = None
        
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
        index = libc_caller.index(state.addr)
        func_name = cfg.functions.values()[index].name
        func_addr = cfg.functions.values()[index].addr
        call_func_addr = state.block().instruction_addrs[len(state.block().instruction_addrs)-1]
        all_func_name = []
        i = 0
        for i in range(0,cfg.functions.values().__len__()):
            all_func_name.append(cfg.functions.values()[i].name)
        self._all_func_name = all_func_name
        #later we will pass ret_addr to unicorn as stop point
        ret_addr = state.block().size + state.addr             
        '''
        Step 2,we step the state up to the call_libc_func
        '''            
        insts = len(state.block().instruction_addrs) - 1
        state.options.discard('INVIVO')
        succs = state.project.factory.successors(state, num_inst=insts).flat_successors
        state = succs[0]        
        self.project = state.project        
        '''
        Step 3,generate a invivo_state which will be used by unicorn engine
        
        return invivo_state who has unicorn option
        '''
        invivo_state = state.copy()
        invivo_state.options |= o.unicorn #add unicorn option to state option
        '''
        Step 4,concrete all the parameters of current function
    
        return invivo_state with concrete parameters
        '''
        SIM_LIBRARIES = angr.procedures.definitions.SIM_LIBRARIES
        #First we need to get all parameters in BVS
        if self.num_args is None:
            self.num_args = self._get_args_num(state,func_name,SIM_LIBRARIES) #This function will be replaced by API provided by fish!!! hardcode now!!!   
        #Second,phrase parameters
        if self.arguments is None:
            self._simcc = state.project.factory.cc() 
            sim_args = [ self._simcc.arg(state, _) for _ in xrange(self.num_args) ]
            self.arguments = sim_args            
        #Third,we concrete all parameters  
        for n in xrange(len(self.arguments)):
            if self.arguments[n].symbolic:    #all parameters must be concrete!
                self.arguments[n] = state.se.solve(self.arguments[n]) #NOT SURE! CHECK IT!
        #Fourth,replace original parameters with concrete parameters
        
        '''
        Step 5,PREPARE IN-VIVO-EXECUTION NOW!        
        '''
        #generate a concrete_state whose parameters are concrete value and start at libc_func_addr
        concrete_state = self.project.factory.call_state(call_func_addr, self.arguments, [], base_state=invivo_state)
        #FIRE!!IN-VIVO!!ENGINE!!NOW!!!
        pg_stoppoints = self.project.factory.simgr(concrete_state).step(n=1, extra_stop_points=[ret_addr])
        nose.tools.assert_equal(len(pg_stoppoints.active), 1) # path should not branch
        p_stoppoints = pg_stoppoints.one_active
        nose.tools.assert_equal(p_stoppoints.addr, ret_addr) # should stop at ret_addr 
        #?????Return what? Maybe pg_stoppoints.active[0]
        #supposed to return angr.engines.successors.SimSuccessors!!!!!
        state = pg_stoppoints.active[0]
        successors.add_successor(state, state.ip, state.se.true, state.unicorn.jumpkind)#NOT SURE!!!!
    
        successors.description = description
        successors.processed = True        
    def _get_args_num(self,state,func_name,SIM_LIBRARIES):
        '''
        FIX IT!
        This function is just for testing,because we are waitting fish!!!
        '''   
        #return corresponding args_num,each function has hardcoded args_num
        args_num = None
        if func_name not in self._all_func_name: #we only process function in libc!!!
            raise Exception #FIX IT!!!!!!!!!!!!!
        '''
        Generate reloc_AND_name to get the owner_name that will be used in follow code
        '''
        reloc_AND_name = {}  # value is reloc,key is the function's name,
        for obj in self.project.loader.initial_load_objects:
            for reloc in obj.imports.itervalues():
                reloc_AND_name[reloc.symbol.name] = reloc 
        for libc_name in reloc_AND_name.keys():
            if func_name == libc_name:
                reloc = reloc_AND_name[libc_name]
        export = reloc.resolvedby
        owner_name = export.owner_obj.provides
        sim_lib = SIM_LIBRARIES[owner_name]
        if not sim_lib.has_implementation(export.name):
            raise Exception #FIX IT
        simprocedure = sim_lib.get(func_name, self.project.arch)
        
        return simprocedure.num_args  
    def _get_libc_addr(self):
        """
        This scans through an objects imports and hooks them with simprocedures from our library whenever possible
        """
        libc_addr_dict = {}  # value is function's name,key is the address of function
        for obj in self.project.loader.initial_load_objects:
            for reloc in obj.imports.itervalues():
                libc_addr_dict[reloc.symbol.name] = reloc.addr
           
        return libc_addr_dict                                
                                                                
    def _check_user_blacklists(self,f):
        """
        Has symbol name `f` been marked for exclusion by any of the user
        parameters?
        """
        blacklists = {} #put the function name you don't want to concrete execute in there
        if f in blacklists:
            return True
        else:
            return False
        
    def _libc_retaddr(self,addr):
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
    
   

