#!/usr/bin/env ruby
def report_error(message)
	puts message + "\r\n\r\n"
	exit!
end

begin
	require 'pry'
	require 'thread'
	require 'net/https'
	require 'nokogiri'
	require 'optparse'
	require 'highline/import'
	require 'crack/json'
rescue LoadError => load_error
	report_error("[-] " + load_error.message + " Run bundle install first")
end


@options = {}
args = OptionParser.new do |opts|
	opts.banner = "qualyscan.rb VERSION: 1.0.0 - UPDATED: 11/03/2015\r\n\r\n"
	opts.banner += "Usage: ./qualyscan.rb [options]\r\n\r\n"
	opts.banner += "\texample: ./qualyscan.rb -q 12345 -t 10.1.1.1,10.2.2.1-100\r\n\r\n"
	opts.on("-q", "--qid [Qualys ID]", "The specific QID you wish to check for") { |qid| @options[:qid] = qid.to_i }
	opts.on("-s", "--sid [Scanner ID]", "The Scanner appliance ID") { |sid| @options[:scanner_id] = sid }
	opts.on("-c", "--check [Scan Reference]", "Scan Reference from launched scan") { |scan_ref| @options[:scan_ref] = scan_ref }
	opts.on("-t", "--targets [Scan Targets]", "Comma delimited list of IP Addresses/Ranges") { |targets| @options[:targets] = targets }
	opts.on("-v", "--verbose", "Enables verbose output\r\n\r\n") { |v| @options[:verbose] = true }
end
args.parse!(ARGV)


def login(creds={})
	# takes a hash of credentials and makes a post
	# returns a string with the Qualys session cookies
	puts "[*] Attempting to authenticate to Qualys Guard.\r\n"
	post = ""
	headers = {}
	uri = get_qualys_uri('session')
	http = setup_http(uri)
	post << "action=login&"
	post << "username=#{creds[:username]}&"
	post << "password=#{creds[:password]}"
	headers['X-Requested-With'] = "qualyscan"
	begin
		response = http.post(uri.path, post, headers)
		if response.body.include? ('Logged in')
			puts "[+] Authentication successful.\r\n" if @options[:verbose]
			return response.header['set-cookie']
		else
			puts "[-] Unable to authenticate with the specified credentials.\r\n"
			exit!
		end
	rescue NoMethodError => login_error
		report_error(login_error.message + " Run ./qualyscan.rb -h for help")
	end
end


def logout(session)
	# Need to logout or else session wills tay active
	puts "[*] Closing the active session.\r\n"
	post = ""
	headers = set_headers(session)
	uri = get_qualys_uri('session')
	http = setup_http(uri)
	post << "action=logout"
	response = http.post(uri.path, post, headers)
	if response.body.include? ('Logged out')
		puts "[+] Successfuly closed active session.\r\n" if @options[:verbose]
	end
end


def launch_scan(session, qid, targets)
	# tries to launch a scan targeting the specified hosts
	# if all goes well should return a scan reference
	puts "[*] Attempting to launch scan on specified targets.\r\n"
	post = ""
	headers = set_headers(session)
	uri = get_qualys_uri('scan')
	http = setup_http(uri)
	ips = split_range(targets)
	post << "action=launch&" +
		"scan_title=QID-#{qid}+qualyscan&"
		if @options[:scanner_id]
			post << "iscanner_id=#{@options[:scanner_id]}&"
		else
			post << "default_scanner=1&"
		end
	post << "option_title=qualyscan&" +
		"ip=#{ips}&"
	begin
		response = http.post(uri.path, post, headers)
		message = parse_xml(response.body)
		unless message[:code] = ""
			logout(session)
			report_error("[-] " + "Code: #{message[:code]} " + message[:text])
		end
		if message[:text] == "New vm scan launched"
			return message[:scan_reference]
		end
	rescue NoMethodError => login_error
		report_error("[-] " + login_error.message + " Run ./qualyscan.rb -h for help")
	end
end


def check_scan_status(session, reference)
	# Queries the status of a given scan returns a 
	# hash with status and a QID from the scan title
	puts "[*] Checking scan status.\r\n"
	post = ""
	headers = set_headers(session)
	uri = get_qualys_uri('scan')
	http = setup_http(uri)
	post << "action=list&" +
		"scan_ref=#{reference}&" +
		"show_status=1" 
	begin
		response = http.post(uri.path, post, headers)
		xml = Nokogiri::HTML(response.body)
		state = {}
		state[:status] = xml.css('state').text
		state[:qid] = response.body.split('[QID-')[1].split(' ')[0]
		return state
	rescue
	end
end


def get_scan_results(session, reference)
	# Retrieves the scan results and parses them
	# returns an array of hashes hash[:ip] and hash[:qid]
	puts "[*] Retrieving scan results.\r\n"
	post = ""
	headers = set_headers(session)
	uri = get_qualys_uri('scan')
	http = setup_http(uri)
	post << "action=fetch&" +
		"scan_ref=#{reference}&" +
		"output_format=json"
	begin
		response = http.post(uri.path, post, headers)
		parse = Crack::JSON.parse(response.body)
		qids = []
		parse.each { |entry| 
			newhash = {}
			newhash[:ip] = entry['ip']
			newhash[:qid] = entry['qid']
			qids << newhash
		}
		return qids
	rescue
	end
end


def print_results(results, qid)
	# processes the results from a scan and prints out
	# hosts that are still vulnerable
	vulnerable_hosts = []
	results.each do |result|
		if result[:qid] == qid.to_i
			vulnerable_hosts << result[:ip]
		end
	end
	if vulnerable_hosts.size > 0
		vulnerable_hosts.each { |host| puts "[-] #{host} still vulnerable to #{qid}"}
	else
		puts "[+] No hosts vulnerable to #{qid}"
	end
end


def parse_xml(blob)
	# Helper method to check error codes 
	message = {}
	xml = Nokogiri::HTML(blob)
	message[:code] = xml.css('code').text
	message[:text] = xml.css('text').text
	message[:scan_id] = xml.css('item')[0].css('value').text
	message[:scan_reference] = xml.css('item')[1].css('value').text
	return message
end


def split_range(list)
	# Helper method to cleanup user supplied IP address ranges
	ips = []
	ranges = []
	list.split(',').each do |entry|
		if entry.include? '-'
			ranges << entry
		else
			ips << entry
		end
	end
	hosts_count = 0
	ranges.each do |range|
		octets = range.split('.')
		(octets[3].split('-')[0].to_i..octets[3].split('-')[1].to_i).each { |node|
			ips << "#{octets[0]}.#{octets[1]}.#{octets[2]}.#{node}"
		}
	end
	return ips.join(',')
end


def credential_prompt
	# Prompt the user for credentials, returns a hash
	creds = {}
	creds[:username] = ask("[*] Enter username: ") { |q| q.echo = true }
	creds[:password] = ask("[*] Enter password: ") { |q| q.echo = false }
	return creds
end


def get_qualys_uri(path)
	return URI.parse("https://qualysguard.qualys.com/api/2.0/fo/#{path}/")
end


def setup_http(uri)
	# returns an http connection on a given host and port
	http = Net::HTTP.new(uri.host, uri.port)
	http.use_ssl = true
	return http
end


def set_headers(session)
	# Specifies headers to use on HTTP requests
	headers = {}
	headers['X-Requested-With'] = "qualyscan"
	headers['Cookie'] = session
	return headers
end


if @options[:qid]
	# if the user supplies a QID that means they are launching a scan
	if @options[:qid].to_s.size > 6 || @options[:qid].to_s.size < 2
		# -q was not an integer between 2 and 6 digits.  Script dies
		report_error("[-] QID must be an integer between 2 and 6 digits in length")
	else
		if !@options[:targets]
			# -t was not provided and script dies
			report_error("[-] You must specify a list of targets.  Run ./qualyscan.rb -h for help")
		else
			session = login(credential_prompt)
			reference = launch_scan(session, @options[:qid], @options[:targets])
			puts "[+] Successfuly launched scan.  Reference: " + reference if reference
		end
	end
	logout(session)
end


if @options[:scan_ref]
	# we are just checking the results of a scan
	session = login(credential_prompt)
	status = check_scan_status(session, @options[:scan_ref])
	if status
		puts "[*] Current status is: " + status[:status] 
	end
	if status[:status] == "Finished"
		# if the scan is finished we should just grab the results
		results = get_scan_results(session, @options[:scan_ref])
		print_results(results, status[:qid])
	end
	logout(session)
end