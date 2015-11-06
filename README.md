# Qualyscan
Just another tool to play with the Qualys API

# Installation
Currently works with Ruby 2.2.1p85 installed via RVM

Install RVM
        $\curl -sSL https://get.rvm.io | bash -s stable --ruby

Install Ruby Gems
    $bundle install

# Help
    $ ./qualyscan.rb -h
    qualyscan.rb VERSION: 1.0.0 - UPDATED: 11/03/2015

    Usage: ./miniscan.rb [options]

        example: ./miniscan.rb -q 12345 -t 10.1.1.1,10.2.2.1-100

        -q, --qid [Qualys ID]            The specific QID you wish to check for
        -s, --sid [Scanner ID]           The Scanner appliance ID
        -n, --name [Scanner name]        The Scanner appliance name
        -c, --check [Scan Reference]     Scan Reference from launched scan
        -t, --targets [Scan Targets]     Comma delimited list of IP Addresses/Ranges
        -v, --verbose                    Enables verbose output

# Launch a new scan
    $ ./miniscan.rb -q 45125 -n appliance1 -t 192.168.1.10,192.168.2.10-16 -v

# Check scan results
    $ ./qualyscan.rb -c scan/xxxx83298.77424
