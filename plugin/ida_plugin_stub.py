import idaapi

class ParascopeStub(idaapi.plugin_t):
    flags = 0
    comment = "Stub for parascope"
    help = "This plugin is a stub and does not provide any functionality."
    wanted_name = "parascope"
    wanted_hotkey = ""

    def init(self):
        print(
            "[WARN] parascope should be used via the command line via "
            "`parascope`, not as a regular plugin. It has been installed in "
            "the same virtual environment used by hcli."
        )
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    if not hasattr(PLUGIN_ENTRY, "_inst"):
        PLUGIN_ENTRY._inst = ParascopeStub()
    return PLUGIN_ENTRY._inst
