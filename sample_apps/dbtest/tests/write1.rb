# Programmer: Chris Bunch
# will eventually be used to test databases
# not yet though :)

ips = ["localhost:8080"]
threads = []
times = []
runs = 10000

# prime the db
`curl http://#{ips[0]}/put -d 'key=0&value=bar'`

ips.each { |addr|
  threads << Thread.new(addr) { |url|
    runs.times { |i| 
      st = Time.now
      `curl http://#{url}/put -d 'key=#{i}&value=bar'` 
      et = Time.now
      total = et - st
      times << total
    }
  }
}

threads.each { |thr| thr.join }

average = 0.0
times.each { |num|
  average += num
}
average /= runs

abort("average put time is #{average} seconds")

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
