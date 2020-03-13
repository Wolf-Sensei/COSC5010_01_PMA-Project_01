# @file: main.py
# @author: Robert Randolplh
# @class: COSC 5010-01
# @assignment: Project 01
# @due: March 13, 2020
# @description: Does basic malware analysis and data scraping for PE files.
# Uses arguments to parse what the user wants to do.
# Given a list of files and directories it will parse all possible files.
# If given a directory it will parse all files in the given directory.
# If the user wishes to explore sub directores the flag [-e] can be used
# Results will be printed to a file
# If the user wants more details the flags [-s] [-i] and [-f] will provide them
# These flags will save the section names, import names, and function names respecfuclly that are found in the PE
# Results are stored in several files in a created directory MalwareAnalysisResults
# Basic results for each file are stored in a single file 000_MalwareAnalysisResults.txt
# Further details are stored in seperate files based on processing order xxx_filename.txt
# Results are overridden between runs. If you wish to store the results move the created folder elsewhere.

# Imports
import pefile
import sys
import os
import datetime
import argparse
import shutil
import string

# Driver
def main():
    # Init
    PEResults = dict()

    #####################################
    ### Arguments
    #####################################

    # Parsing passed arguments
    # Usage: [-i] [-f] [paths]
    parser = argparse.ArgumentParser(prog="MalwareAnalysis")
    parser.add_argument('-s', action='store_true', help='Save section names')
    parser.add_argument('-i', action='store_true', help='Save import names')
    parser.add_argument('-f', action='store_true', help='Save function names')
    parser.add_argument('-e', action='store_true', help='Explore sub-directories of parent directories')
    parser.add_argument('paths', nargs=argparse.REMAINDER, type=str, help='List of file or dir paths')
    args = parser.parse_args()

    #####################################
    ### File/Directory Paths
    #####################################

    #############
    # For testing
    #############
    args.paths.append('C:\Riot Games\Riot Client\RiotClientServices.exe')
    args.paths.append('C:\Temp')

    # Getting files from file and dir paths from args
    (files, invalid) = compileFileList(args.paths, args.e)

    # Printing out invalid paths if any
    for inv in invalid:
        print('Error: Invalid path: ', inv)

    # Checking if there are any files to be processed
    # If not, prints out an error and a usage statement, and then exits
    if len(files) == 0:
        print('Error: No files to process.')
        print('Usage: [-s] [-i] [-f] [-s] [paths]')
        print('[-s] Save section names | Optional')
        print('[-i] Save import names | Optional')
        print('[-f] Save function names | Optional')
        print("[-e] Explore sub-directories of parent dir | Optional")
        print('[paths] A list of file and dir paths')
        sys.exit()      

    #####################################
    ### Processing Files
    #####################################

    # Opening each file and processing it in PE
    for f in files:
        # Attempting to open file in PE
        print('Processing: ', f)
        pe = openFileInPE(f)
        if pe is None: continue
        pe.parse_data_directories()

        # Attempting to get compile time
        compileTime = getCompileTime(pe)

        # Attempting to get sections, imports, and functions
        sections = getSections(pe)
        imports = getImports(pe)
        functions = getFunctions(imports)

        # Calculating packed/obfuscation likelyhood
        # @POLikelyhood: 0 Very Likely; 1 Likely; 2 Unknown; 3 Unlikely; 4 Very Unlikely
        POLikelyhood = calculatePOLikelyhood(sections, functions)
        PEResults[f] = (POLikelyhood, compileTime, sections, imports, functions)
        print('Finished processing: ', f)

    # Creating directory for results
    try:
        os.mkdir('MalwareAnalysisResults')
    except:
        try:
            shutil.rmtree('MalwareAnalysisResults')
            os.mkdir('MalwareAnalysisResults')
        except:
            pass

    # Outputing results to file(s)
    index = 0
    with open('MalwareAnalysisResults\\000_MalwareAnalysisResults.txt', 'w') as output:
        for fileName, (POLikelyhood, compileTime, sections, imports, functions) in PEResults.items():
            index += 1
            # Basic Information
            output.writelines([fileName, '\n\t'])
            output.writelines(['Packed/Obfuscated: ', convertPOLikelyhood(POLikelyhood)])
            output.writelines([' || Compile Time: ', str(compileTime), ' [UTC]'])
            output.writelines([' || Sections: ', str(len(sections))])
            output.writelines([' || Imports: ', str(len(imports))])
            output.writelines([' || Functions: ', str(len(functions)), '\n'])
            # Detailed information if desired
            if args.s or args.i or args.f:
                outFile = str(index).zfill(3) + '_' + os.path.basename(fileName) + '.txt'
                output.writelines(['\tExtra Information in file: ', outFile, '\n'])
                with open('MalwareAnalysisResults\\' + outFile, 'w') as output2:
                    if args.s:
                        output2.writelines(['='*10 + 'Sections' + '='*10 + '\n'] + [''.join(filter(lambda x: x in set(string.printable), s.decode('utf-8') + ' || ')) for s in sections] + ['\n\n'])
                    if args.i:
                        output2.writelines(['='*10 + 'Imports' + '='*10 + '\n'] + [''.join(filter(lambda x: x in set(string.printable), i.dll.decode('utf-8') + ' || ')) for i in imports] + ['\n\n'])
                    if args.f:
                        output2.writelines(['='*10 + 'Functions' + '='*10 + '\n'] + [f + ' || ' for f in functions] + ['\n\n'])

# Compiles a list of of files from the given paths
# If the arg is a file then opens and does analysis
# If the arg is a dir then opens and does analysis on all avaliable files.
# If it is neither, then the arg is ignored and passed back
# @explore whether to also include files in sub directories
def compileFileList(paths, explore):
    # Init
    files = list()
    invalid = list()

    # Compiling list of files to process
    for path in paths:
        if os.path.isfile(path):    # File
            files.append(path)
        elif os.path.isdir(path):   # Dir : Getting files in dir
            dirPaths = [os.path.join(path, p) for p in os.listdir(path)]
            dirFiles = [f for f in dirPaths if os.path.isfile(f)]
            files += dirFiles
            if explore:             # Sub Dir : Exploring sub directories if wanted @explore
                dirs = [d for d in dirPaths if os.path.isdir(d)]
                (dirFiles, _) = compileFileList(dirs, explore)
                files += dirFiles
        else:                       # Invalid path
            invalid.append(path)
    
    return (files, invalid)

# Opens a file in PE if possible
def openFileInPE(path):
    # Init
    pe = None

    print('Opening file', end='\r')
    try:
        pe = pefile.PE(path, fast_load=True)
    except:
        print("Error: Couldn't open file ", path, 'in PE')

    return pe

# Returns the compile time if possible
def getCompileTime(pe):
    # Init
    compileTime = None

    print('Getting Compile time', end='\r')
    try:
        compileTime = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)
    except:
        print('Unable to determine compile time')

    return compileTime

# Returns a list of sections names
def getSections(pe):
    # Init
    sections = list()

    # Getting sections
    print('Getting Sections', end='\r')
    for section in pe.sections:
        sections.append(section.Name)

    return sections

# Returns a list of imports
def getImports(pe):
    # Init
    imports = None

    print('Getting Imports', end='\r')
    try:
        imports = pe.DIRECTORY_ENTRY_IMPORT
    except:
        print('Unable to determine imports')

    return imports

# Returns a list of functions from an import list
def getFunctions(imports):
    # Init
    functions = list()

    # Checking if imports is empty
    if imports is None: return None

    print('Getting Functions', end='\r')
    for imp in imports:
        for func in imp.imports:
            try:
                functions.append(func.name.decode('utf-8'))
            except:
                continue

    return functions

# Calculates and returns the likelyhood that the file is packed or obfuscated
# @result: 0 Very Likely; 1 Likely; 2 Unknown; 3 Unlikely; 4 Very Unlikely
def calculatePOLikelyhood(sections, functions):
    # Init
    sectionsPacked = True

    print('Calculating Packed/ObfuscationLikelyhood', end='\r')

    # Comparing Common Section Names with sections list
    if '.text' or '.rdata' or '.data' or '.rsrc' in sections: sectionsPacked = False

    # Comparing number of imports (Using personal xp, which isn't a lot)
    funcNum = len(functions)
    if funcNum <= 10: result = 0     # Very likely
    elif funcNum <= 20: result = 1   # Likely
    elif funcNum <= 30: result = 2   # unknown
    elif funcNum <= 40: result = 3   # unlikely
    else: result = 4                 # Very unlikely

    # Determining overall packed/obuscated likelyhood
    if sectionsPacked: result -= 2
    else: result += 2

    # Checking bounds
    if result < 0: result = 0
    if result > 4: result = 4

    return result

# Converts the POLikelyhood integer into a string equivalent
def convertPOLikelyhood(POLikelyhood):
    if POLikelyhood == 0: return "Very Likely"
    elif POLikelyhood == 1: return "Likely"
    elif POLikelyhood == 2: return "Unknown"
    elif POLikelyhood == 3: return "Unlikely"
    elif POLikelyhood == 4: return "Very Unlikely"
    else: return "Error"

# Running main when script starts
if __name__ == '__main__': main()