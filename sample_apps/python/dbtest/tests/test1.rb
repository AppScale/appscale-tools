# Programmer: Chris Bunch
# will eventually be used to test databases
# not yet though :)

addr = "localhost:8080"

# here's how to put with a key
`curl http://#{addr}/put -d 'key=foo&value=bar'`

# here's how to get with a key
response = `curl http://#{addr}/get -d 'key=foo'`

if response == "bar"
  puts "yay!"
else
  puts "fail! saw [#{response}], expected [bar]"
end
# check if its a bar
