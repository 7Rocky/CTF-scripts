#!/usr/bin/env ruby

puts "CTFlearn{#{File.readlines('data.dat').filter do |line|  
  (line.count('0') % 3).zero? or line.count('1').even?
end.length}}"
