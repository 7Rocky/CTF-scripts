#!/usr/bin/env ruby

counter = 0

File.readlines('data.dat').each do |line|
  counter += 1 if line.count('0') % 3 == 0 or line.count('1') % 2 == 0  
end

puts "CTFlearn{#{counter}}"
