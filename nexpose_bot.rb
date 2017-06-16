#! /usr/bin/env ruby


require 'nexpose'
require 'rubygems'
require 'pp'
require 'yaml'
require 'csv'
include Nexpose



# ###########   Nexpose Login  ####################
config = YAML.load(File.read("config/nexpose.yml"))["server_config"]
@nsc = Connection.new(config["host"], config["username"], config["password"])
@nsc.login
##################################################

# Action to take on every line of csv file with header row
def process(report)
    puts "Code to process csv goes here for #{report}"

 CSV.foreach(report, headers: true) do |row|
# **** actions here are operated on every row in the csv ****
   puts row['Site Name']
 end
end


######### Where the magic is. You've got report naming, sql query, & time monitoring.
def adhoc_report(site)
    start_time = Time.now

    report_name = "reports/#{site.name}.csv"
    puts "Generating #{report_name}. Be patient. Get some coffee."

    query = %q{WITH
vuln_urls AS (
      SELECT vulnerability_id, array_to_string(array_agg(reference), ' , ') AS references
      FROM dim_vulnerability_reference 
      GROUP BY vulnerability_id
)


select da.ip_address, da.host_name, dos.description as operating_system, dv.title as vuln_title, round(dv.riskscore::numeric,0) as vuln_riskscore, 
CASE
WHEN (dv.riskscore >= 800) then 'Very High'
WHEN (dv.riskscore >= 600 AND dv.riskscore <= 799) then 'High'
WHEN (dv.riskscore >= 400 AND dv.riskscore <= 599) then 'Medium'
WHEN (dv.riskscore >= 200 AND dv.riskscore <= 399) then 'Low'
WHEN (dv.riskscore <= 199) then 'Very Low'
END AS vuln_severity,
proofastext(dv.description) as vuln_description, 
proofastext(favi.proof) as vuln_proof, vu.references, favi.port as "port", dv.date_added as vuln_date_into_nexpose, 
to_char(favi.date, 'YYYY-mm-dd') as asset_last_scan

FROM fact_asset_vulnerability_instance favi
JOIN dim_vulnerability dv USING (vulnerability_id)
JOIN dim_asset da USING (asset_id)
JOIN dim_operating_system dos USING (operating_system_id)
JOIN dim_vulnerability_reference dvr USING (vulnerability_id)
JOIN vuln_urls vu USING (vulnerability_id)
WHERE dv.riskscore >= 600
ORDER BY dv.riskscore DESC}

    report_config = Nexpose::AdhocReportConfig.new(nil, 'sql', site.id)
    report_config.add_filter('version', '2.3.0')
    report_config.add_filter('query', query)
    report_output = report_config.generate(@nsc)

    end_time = Time.now

    File.open(report_name, "w+") do |file|
      file.write report_output
    end

    csv_output = CSV.parse(report_output.chomp, { :headers => :first_row })
    file_length = csv_output.entries.count

    #calculates duration for file creation
    ttg =  ( (end_time - start_time) / 60).round(1)
    puts "\t. . . Complete after #{ttg} minutes and is #{file_length} lines long!"
    report_name
end
###################################################


# Stores the output in an array and searches all sites
@output = []
# You can pull sites from the console with either a regex search
# by name or from a hardcoded array or names
sites = @nsc.list_sites.select {|s| s.name.include?("Public")}
#sites = ['Public Scan Engine']
sites.each do |site|
    @output << adhoc_report(site)
end


# Output reports to the screen
@output.each do |report|
    process report
end
