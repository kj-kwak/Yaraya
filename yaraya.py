# -*- coding: utf-8 -*-

import binascii, re, sys, os, argparse, math, sqlite3, hashlib, yara, csv, configparser
try:
    import magic
except:
    print("Could not import magic for file identification. Use: pip install python-magic")


def parseArgument():
    parser = argparse.ArgumentParser(
        description='Yabin - Signatures and searches malware')
    parser.add_argument(
        '-y', '--yararule', help='Generate yara rule for the file or folder', required=False)
    parser.add_argument(
        '-t', '--target', help='Target Directory to scan', required=False)
    return parser


class YarayaClass:
    def __init__(self, arg_yararule, arg_target, yararule_basedir, sample_basedir):
        try:
            self.yaraBaseDir = yararule_basedir
            self.yararule = arg_yararule
            self.yarapath = self.yaraBaseDir + self.yararule
            self.target = arg_target
            self.sample_basedir = sample_basedir
            
        except Exception as e:
            print("Init Exception : {}".format(e))

    def YaraSearch(self):     
        try:
            print("Compiling rules from {}".format(self.yarapath))
            self.rules = yara.compile(self.yarapath)
        except Exception as e:
            print("Compile Exception: {}".format(e))

        if self.target is None:
            self.target = self.sample_basedir 
        print(self.target)

        """
        Scan all method that recursively walks the directory and calls scan and unpack
        """
        identifier = "/"
        csvfilename = self.yararule.split(".")[0] + "_Matched_FileList.csv"
        with open(csvfilename,"w") as csvfile:
            fieldnames = ['Filename', 'MD5', 'SHA256', 'YARARULE']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for root, directories, files in os.walk(self.target):
                for file in files:
                    if file.find(".yar") > -1:
                        continue
                    elif file.find(".yara") > -1:
                        continue
                    work_file = os.path.join(root, file)
                    try:
                        matches = self.rules.match(work_file)
                        if matches:
                            print("{}\n{}\n".format(work_file, matches))
                            path = root+identifier+file
                            md5 = hashlib.md5(open(path,"rb").read()).hexdigest()
                            sha256 = hashlib.sha256(open(path,"rb").read()).hexdigest()
                            sha1 = hashlib.sha1(open(path,"rb").read()).hexdigest()
                            writer.writerow({'Filename' : path, 'MD5' : md5, 'SHA256' : sha256, 'YARARULE' : matches})
                    except Exception as e:
                        print("Scan Exception : {}".format(e))
                        
                    #else:
                    #    continue

def main():
    config = configparser.ConfigParser()
    config.read('yaraya.config')
    yararule_basedir = config['DEFAULT']['yararule_base_dir']
    sample_basedir = config['DEFAULT']['sample_repository_base_dir']

    args = parseArgument().parse_args()
    ys = YarayaClass(args.yararule, args.target, yararule_basedir, sample_basedir)
    ys.YaraSearch()


if "__main__" == __name__:
    try:
        main()
    except KeyboardInterrupt as error:
        print("Error!")
