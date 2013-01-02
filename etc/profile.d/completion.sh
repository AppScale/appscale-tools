function repo()
{
    cd /srv/appscale/repo/$@
}

_list_appscale_repos()
{
    local cur

    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    COMPREPLY=($( compgen -W "$(find /srv/appscale/repo -maxdepth 2 -type d -name .git | sed -e 's,.*/\(.*\)/.git,\1,')" -- $cur ))
}
complete -F _list_appscale_repos repo
