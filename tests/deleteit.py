import nose
import angr
import pickle
import re
from angr import options as so
from nose.plugins.attrib import attr

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../'))


def test_simcc():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/vuln_stacksmash'),
                     use_sim_procedures=True)

    #Generate a SimCC instance
    simcc = p.factory.cc()
    print type(simcc)


if __name__ == '__main__':

    test_simcc()