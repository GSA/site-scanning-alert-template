# site-scanning-alert-template
A template for using GitHub Actions and Issues to set up alerts for changes in Site Scanning results 

## Models

#### Model 1

For a set list of `initial_domain` entries, create an issue when there is a change in value to the `live` field, the `status_code` field, or the `primary_scan_status` field.  Something along the line of: 

Ideally, all of the alerts like this would be combined into a single issue.  So an issue might look like:  

Title: Possible website issues
Body: 

````
❗ Site Scanning results have changed for websites that you are monitoring:  

initial_domain: blog.acme.gov
live: TRUE -> FALSE 

initial_domain: blog.acme.gov
status_code: 200 -> 503 

initial_domain: calendar.acme.gov
primary_scan_status: completed -> timeout 

Please investigate as appropriate.
````

If that was cumbersome, we could discuss having individual issues generated for each initial domain.  

My suggestion would be to compare either the CSV or JSON `-latest` snapshot file to the `previous` snapshot file, however my heart is open to instead querying the API, not for a change in value but for the existence of a value, e.g. when a site on the list returns a status code of: 301. 302. 307. 400, 401, 402, 403, 404, 405, 500, 501, 502, 503.  

#### Model 2

The same behavior as Model 1 except for all records that have a certain initial_base_domain (e.g. cpsc.gov).  

## Notes
* [These](https://github.com/GSA/site-scanning/issues/1672) [issue](https://github.com/GSA/site-scanning/issues/1968) templates are good starting points and could be largely copied.  
