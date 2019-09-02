import os
from optparse import OptionParser
from steelscript.commands.mkworkspace import Command

# Parse arguments
parser = OptionParser()
parser.add_option("--overwrite",
                  action="store_true", dest="overwrite", default=False,
                  help="overwrite edited examples with collected examples")
(options, args) = parser.parse_args()

# Get the file's current directory
dirpath = os.path.dirname(os.path.realpath(__file__))
# Collect all the examples into that directory
Command.collect_examples(dirpath, options.overwrite)
