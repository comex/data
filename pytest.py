import glob, sys
for path in glob.glob('build/lib.*'): sys.path.append(path)
import data
