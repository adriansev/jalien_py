//usr/bin/env -S root.exe -b -q -l -e ".x ${0}" ; exit $?
{
int loaded = gSystem->Load("libJAliEnROOT");
TGrid* alien = TGrid::Connect("alien://");
TString cmd_str ("pwd");
TGridResult* cmd_result = gGrid->Command(cmd_str.Data());
TString result_str = cmd_result->GetKey(0,cmd_str.Data());
cout << result_str << endl;
return 0;
}
