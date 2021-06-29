#! /usr/bin/env python

from scapy.all import *
from layers.scion import *
from layers.telemetry import *
from layers.scmp import *
from layers.bfd import *


if __name__ == "__main__":
    interact(mydict=globals())
