//usr/bin/env -S root.exe -b -q -l -e ".x ${0}" ; exit $?
{
// example macro for accessing ALICE files from ROOT without having the JAliEn-ROOT plugin compiled and installed
// NOT WORKING YET

std::cout << "Make sure you did in environment: export XRD_LOCALMETALINKFILE=1" << std::endl;
setenv("XRD_LOCALMETALINKFILE", "1", 1);

// define the remote lfn
std::string lfn {"/alice/cern.ch/user/a/admin/referenceData/standaloneFile.root"};
std::string ext {".root"};

// load the alien.py
auto rez = TPython::Exec("exec(\"\"\"\ntry:\n    from alienpy.alien import *\nexcept Exception:\n    try:\n        from xjalienfs.alien import *\n    except Exception:\n        print(\"Can't load alienpy, exiting...\")\n        sys.exit(1)\n\"\"\")");
if (!rez) {
    std::cout << "Error importing alienpy!" << std::endl;
    gApplication->Terminate(1);
    }

rez = TPython::Exec("setup_logging()");
rez = TPython::Exec("wb = InitConnection()");

// python function for obtaining a meta file
std::string meta_file_cmd = "ret = DO_lfn2uri(wb,[ 'meta', '" + lfn  + "'])";
rez = TPython::Exec(meta_file_cmd.c_str());

auto exitcode = (int)TPython::Eval("ret.exitcode");
auto stdout = (std::string)TPython::Eval("ret.out");
auto stderr = (std::string)TPython::Eval("ret.err");

if (exitcode != 0) {
    std::cout << "Error getting the metafile!\n" << stderr << std::endl;
    gApplication->Terminate(1);
    }

//std::string meta_filepath = "root://localfile/" + stdout;

bool is_root = true;
if ( 0 != lfn.compare(lfn.length() - ext.length(), ext.length(), ext)) { is_root = false; meta_filepath.append( "?filetype=raw"); }

std::unique_ptr<TFile> f( TFile::Open(meta_filepath.c_str()) );
if (!f || f->IsZombie()) {
    std::cout << "Error opening file" << std::endl;
    exit(1);
    }

// This is reading the file; No idea at this point how to access to content of a raw file
const auto file_size = f->GetSize();
std::cout << "Size of the file: " << file_size << std::endl;

if (is_root) { f->Print(); }

}

