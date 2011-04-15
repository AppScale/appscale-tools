#!/usr/local/bin/ruby -w
# Programmer: Chris Bunch
# mapper-ruby.rb: Solves part of the EP parallel benchmark via the 
# MapReduce framework as follows:
# Input: Takes in ranges of k values to compute over STDIN.
# Output: list [l, X_k, Y_k]

A = 5 ** 13
S = 271828183
MIN_VAL = 2 ** -46
MAX_VAL = 2 ** 46

def generate_random(k)
  xk = (A ** k) * S % MAX_VAL
  MIN_VAL * xk
end

def ep(k)
  k = Integer(k)
  
  xj = generate_random(k)
  yj = generate_random(k+1)
  
  t = xj * xj + yj * yj
  
  if t <= 1
    xk = xj * Math.sqrt(-2 * Math.log(t) / t)
    yk = yj * Math.sqrt(-2 * Math.log(t) / t)
    
    max = [xk.abs, yk.abs].max
    l = max.floor
    puts "#{l}\t#{xk}\t#{yk}"
  end
end

loop {
  input = STDIN.gets
  break if input.nil?
  start, fin = input.chomp.split
  start = Integer(start)
  fin = Integer(fin)
  current = start
  loop {
    ep(current)
    current = current + 2
    break if current > fin
  }
}
