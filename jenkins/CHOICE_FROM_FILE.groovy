class CHOICE_FROM_FILE {

	// Used by jenkins interface to read in from a file to populate a choice list

    static getList(String file_name) {

        def ret = [];
        def deflist = new File(file_name);

        deflist.eachLine() { line ->
            ret << line
        }

        return ret

    }
}

