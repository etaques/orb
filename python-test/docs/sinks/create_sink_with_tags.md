## Scenario: Create sink with tags 
## Steps:
1 - Create a sink with one pair (key:value) of tags

- REST API Method: POST
- endpoint: /sinks
- header: {authorization:token}


## Expected Result:
- Request must have status code 201 (created) and the sink must be created
- Tags for sink just serve to filter the sinks