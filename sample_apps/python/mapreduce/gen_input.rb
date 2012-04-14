#!/usr/local/bin/ruby -w
# Programmer: Chris Bunch
# gen_input: Generates input in such a way that Map will be able to pick it
# up and compute EB

POWER = 10
N = 2 ** POWER
BUCKET_SIZE = 2 ** (POWER / 2)

file_system = "local"

vals = (1 .. N / BUCKET_SIZE).to_a
vals = vals.map { |i| i = BUCKET_SIZE * i }

output = ""
vals.each_index { |i|
  if i == 0
    start = 0
  else
    start = vals[i-1]
  end
  
  output << "#{start+1}\t#{vals[i]}\n"
}

if file_system == "local"
  File.open("input", "w+") { |file| file.write(output) }
else

end
