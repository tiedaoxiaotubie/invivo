import nose
import angr
import pickle
import re
from angr import options as so
from nose.plugins.attrib import attr

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../'))


def test_invivo():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/vuln_stacksmash'),
                     use_sim_procedures=True)

    # test STOP_NORMAL, STOP_STOPPOINT
    invivo_state = p.factory.entry_state(add_options=so.invivo)

    simgr = p.factory.simgr(invivo_state)
    simgr.run()



if __name__ == '__main__':

    test_invivo()