//usr/bin/env -S root.exe -b -q -l "${0}" ; exit $?
{
TPython::Exec("exec(\"\"\"\ntry:\n    from alienpy import alien\nexcept Exception as e:\n    try:\n        from xjalienfs import alien\n    except Exception as e:\n        print(\"Can't load alienpy, exiting...\")\n        sys.exit(1)\n\"\"\")");
TPython::Exec("alien.retf_print(alien.DO_tokeninfo())");
}

