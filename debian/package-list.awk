# Generate a package list from control file.

function addlinepackages(line) {
    split(line, list, ",");
    for (i in list) {
        gsub("\\\\", "", list[i])
        if (length(list[i]) > 0) {
            packages[count] = list[i]
            count += 1
        }
    }
}

BEGIN {
    flag = 0
    count = 1
}

/^Depends:/ {
    sub("^Depends:", "", $0)
    addlinepackages(line)

    # Identify subsequent lines as part of the package list.
    flag = 1
}

/^ / {
    if (flag != 0) {
        addlinepackages($0)
    }
}

/^Description:/ {
    # Mark the end of the package list.
    flag = 0
}

END {
    for (i in packages)
    printf("%s ", packages[i])
}
