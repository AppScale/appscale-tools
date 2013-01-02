export APPSCALE_TOOLS_PATH=/usr/local/appscale-tools
export PATH=${PATH}:${APPSCALE_TOOLS_PATH}/bin

keygen()
{
    # create ssh private key if it is not exists.
    test -e /root/.ssh/id_rsa || ssh-keygen -q -t rsa -f /root/.ssh/id_rsa -N ""
}
