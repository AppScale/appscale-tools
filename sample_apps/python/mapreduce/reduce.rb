#!/usr/local/bin/ruby -w
# Programmer: Chris Bunch
# reducer-ruby.rb: Solves part of the EP parallel benchmark via the 
# MapReduce framework as follows:
# Input: list [l, X_k, Y_k]
# Output: [l, sum(X_k), sum(Y_k)]

current_l = nil

x_count = 0
y_count = 0

sum_x = 0.0
sum_y = 0.0

loop {
  input = STDIN.gets
  break if input.nil?
  l, x, y = input.chomp.split
  l = Integer(l)
  x = Float(x)
  y = Float(y)
  
  current_l = l if current_l.nil?
  
  if l != current_l
    puts "bucket = #{current_l}, |x| = #{x_count}, |y| = #{y_count}"
    current_l = l
    x_count = 0
    y_count = 0
  end
  
  sum_x = sum_x + x
  sum_y = sum_y + y

  abs_x = x.abs
  abs_y = y.abs

  if abs_x > abs_y
    x_count = x_count + 1
  else
    y_count = y_count + 1 
  end
}

puts "bucket = #{current_l}, |x| = #{x_count}, |y| = #{y_count}"

puts "sum x = #{sum_x}, sum y = #{sum_y}"
