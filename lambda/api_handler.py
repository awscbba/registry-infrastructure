import json
import boto3
import uuid
import os
from datetime import datetime
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')

# Custom JSON encoder to handle Decimal objects from DynamoDB
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            # Convert decimal to int if it's a whole number, otherwise to float
            if obj % 1 == 0:
                return int(obj)
            else:
                return float(obj)
        return super(DecimalEncoder, self).default(obj)

def lambda_handler(event, context):
    print(f"Event: {json.dumps(event)}")
    
    # Get table names from environment
    people_table_name = os.environ.get('PEOPLE_TABLE_NAME', 'PeopleTable')
    projects_table_name = os.environ.get('PROJECTS_TABLE_NAME', 'ProjectsTable')
    subscriptions_table_name = os.environ.get('SUBSCRIPTIONS_TABLE_NAME', 'SubscriptionsTable')
    
    people_table = dynamodb.Table(people_table_name)
    projects_table = dynamodb.Table(projects_table_name)
    subscriptions_table = dynamodb.Table(subscriptions_table_name)
    
    # Extract HTTP method and path
    http_method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')
    path_parameters = event.get('pathParameters') or {}
    
    try:
        # Health check
        if path == '/health':
            return {
                'statusCode': 200,
                'headers': get_cors_headers(),
                'body': json.dumps({'status': 'healthy', 'service': 'people-register-api-global-with-projects'}, cls=DecimalEncoder)
            }
        
        # PEOPLE ENDPOINTS (existing)
        elif path == '/people':
            if http_method == 'GET':
                response = people_table.scan()
                people = response.get('Items', [])
                return {
                    'statusCode': 200,
                    'headers': get_cors_headers(),
                    'body': json.dumps(people, cls=DecimalEncoder)
                }
            
            elif http_method == 'POST':
                return create_person(people_table, event)
        
        elif path.startswith('/people/'):
            person_id = path_parameters.get('id')
            if not person_id:
                return error_response(400, 'Person ID is required')
            
            if http_method == 'GET':
                return get_person(people_table, person_id)
            elif http_method == 'PUT':
                return update_person(people_table, person_id, event)
            elif http_method == 'DELETE':
                return delete_person(people_table, person_id)
        
        # PROJECTS ENDPOINTS (new)
        elif path == '/projects':
            if http_method == 'GET':
                return get_projects(projects_table)
            elif http_method == 'POST':
                return create_project(projects_table, event)
        
        elif path.startswith('/projects/'):
            project_id = path_parameters.get('id')
            if not project_id:
                return error_response(400, 'Project ID is required')
            
            # Handle nested routes
            if path.endswith('/subscribers'):
                return get_project_subscribers(subscriptions_table, people_table, project_id)
            elif '/subscribe/' in path:
                person_id = path.split('/subscribe/')[-1]
                return subscribe_person_to_project(subscriptions_table, project_id, person_id, event)
            elif '/unsubscribe/' in path:
                person_id = path.split('/unsubscribe/')[-1]
                return unsubscribe_person_from_project(subscriptions_table, project_id, person_id)
            else:
                if http_method == 'GET':
                    return get_project(projects_table, project_id)
                elif http_method == 'PUT':
                    return update_project(projects_table, project_id, event)
                elif http_method == 'DELETE':
                    return delete_project(projects_table, subscriptions_table, project_id)
        
        # SUBSCRIPTIONS ENDPOINTS (new)
        elif path == '/subscriptions':
            if http_method == 'GET':
                return get_subscriptions(subscriptions_table)
            elif http_method == 'POST':
                return create_subscription(subscriptions_table, event)
        
        elif path.startswith('/subscriptions/'):
            subscription_id = path_parameters.get('id')
            if http_method == 'DELETE':
                return delete_subscription(subscriptions_table, subscription_id)
        
        # ADMIN ENDPOINTS (new)
        elif path == '/admin/dashboard':
            return get_admin_dashboard(people_table, projects_table, subscriptions_table)
        
        # Default response for unmatched routes
        return error_response(404, 'Route not found')
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return error_response(500, 'Internal server error')

def get_cors_headers():
    return {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key'
    }

def error_response(status_code, message):
    return {
        'statusCode': status_code,
        'headers': get_cors_headers(),
        'body': json.dumps({'error': message}, cls=DecimalEncoder)
    }

# PEOPLE FUNCTIONS (existing, updated)
def create_person(people_table, event):
    body = json.loads(event.get('body', '{}'))
    person_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    # Address structure for global use
    address = body.get('address', {})
    if address:
        clean_address = {
            'street': address.get('street', ''),
            'city': address.get('city', ''),
            'state': address.get('state', ''),
            'country': address.get('country', '')
        }
        if address.get('postalCode'):
            clean_address['postalCode'] = address.get('postalCode')
    else:
        clean_address = {}
    
    person = {
        'id': person_id,
        'firstName': body.get('firstName'),
        'lastName': body.get('lastName'),
        'email': body.get('email'),
        'phone': body.get('phone'),
        'dateOfBirth': body.get('dateOfBirth'),
        'address': clean_address,
        'createdAt': now,
        'updatedAt': now
    }
    
    people_table.put_item(Item=person)
    
    return {
        'statusCode': 201,
        'headers': get_cors_headers(),
        'body': json.dumps(person, cls=DecimalEncoder)
    }

def get_person(people_table, person_id):
    response = people_table.get_item(Key={'id': person_id})
    if 'Item' not in response:
        return error_response(404, 'Person not found')
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(response['Item'], cls=DecimalEncoder)
    }

def update_person(people_table, person_id, event):
    body = json.loads(event.get('body', '{}'))
    now = datetime.utcnow().isoformat()
    
    response = people_table.get_item(Key={'id': person_id})
    if 'Item' not in response:
        return error_response(404, 'Person not found')
    
    person = response['Item']
    
    # Handle address update for global use
    if body.get('address'):
        address = body.get('address', {})
        clean_address = {
            'street': address.get('street', ''),
            'city': address.get('city', ''),
            'state': address.get('state', ''),
            'country': address.get('country', '')
        }
        if address.get('postalCode'):
            clean_address['postalCode'] = address.get('postalCode')
        person['address'] = clean_address
    
    person.update({
        'firstName': body.get('firstName', person.get('firstName')),
        'lastName': body.get('lastName', person.get('lastName')),
        'email': body.get('email', person.get('email')),
        'phone': body.get('phone', person.get('phone')),
        'dateOfBirth': body.get('dateOfBirth', person.get('dateOfBirth')),
        'updatedAt': now
    })
    
    people_table.put_item(Item=person)
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(person, cls=DecimalEncoder)
    }

def delete_person(people_table, person_id):
    response = people_table.delete_item(
        Key={'id': person_id},
        ReturnValues='ALL_OLD'
    )
    
    if 'Attributes' not in response:
        return error_response(404, 'Person not found')
    
    return {
        'statusCode': 204,
        'headers': get_cors_headers(),
        'body': ''
    }

# PROJECT FUNCTIONS (new)
def get_projects(projects_table):
    response = projects_table.scan()
    projects = response.get('Items', [])
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(projects, cls=DecimalEncoder)
    }

def create_project(projects_table, event):
    body = json.loads(event.get('body', '{}'))
    project_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    project = {
        'id': project_id,
        'name': body.get('name'),
        'description': body.get('description', ''),
        'status': body.get('status', 'active'),
        'createdBy': body.get('createdBy', 'admin'),
        'maxParticipants': body.get('maxParticipants'),
        'startDate': body.get('startDate'),
        'endDate': body.get('endDate'),
        'createdAt': now,
        'updatedAt': now
    }
    
    projects_table.put_item(Item=project)
    
    return {
        'statusCode': 201,
        'headers': get_cors_headers(),
        'body': json.dumps(project, cls=DecimalEncoder)
    }

def get_project(projects_table, project_id):
    response = projects_table.get_item(Key={'id': project_id})
    if 'Item' not in response:
        return error_response(404, 'Project not found')
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(response['Item'], cls=DecimalEncoder)
    }

def update_project(projects_table, project_id, event):
    body = json.loads(event.get('body', '{}'))
    now = datetime.utcnow().isoformat()
    
    response = projects_table.get_item(Key={'id': project_id})
    if 'Item' not in response:
        return error_response(404, 'Project not found')
    
    project = response['Item']
    project.update({
        'name': body.get('name', project.get('name')),
        'description': body.get('description', project.get('description')),
        'status': body.get('status', project.get('status')),
        'maxParticipants': body.get('maxParticipants', project.get('maxParticipants')),
        'startDate': body.get('startDate', project.get('startDate')),
        'endDate': body.get('endDate', project.get('endDate')),
        'updatedAt': now
    })
    
    projects_table.put_item(Item=project)
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(project, cls=DecimalEncoder)
    }

def delete_project(projects_table, subscriptions_table, project_id):
    # First, delete all subscriptions for this project
    response = subscriptions_table.query(
        IndexName='ProjectIndex',
        KeyConditionExpression='projectId = :projectId',
        ExpressionAttributeValues={':projectId': project_id}
    )
    
    for subscription in response.get('Items', []):
        subscriptions_table.delete_item(Key={'id': subscription['id']})
    
    # Then delete the project
    response = projects_table.delete_item(
        Key={'id': project_id},
        ReturnValues='ALL_OLD'
    )
    
    if 'Attributes' not in response:
        return error_response(404, 'Project not found')
    
    return {
        'statusCode': 204,
        'headers': get_cors_headers(),
        'body': ''
    }

# SUBSCRIPTION FUNCTIONS (new)
def get_subscriptions(subscriptions_table):
    response = subscriptions_table.scan()
    subscriptions = response.get('Items', [])
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(subscriptions, cls=DecimalEncoder)
    }

def create_subscription(subscriptions_table, event):
    body = json.loads(event.get('body', '{}'))
    subscription_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    subscription = {
        'id': subscription_id,
        'projectId': body.get('projectId'),
        'personId': body.get('personId'),
        'status': body.get('status', 'active'),
        'subscribedAt': now,
        'subscribedBy': body.get('subscribedBy', 'admin'),
        'notes': body.get('notes', '')
    }
    
    subscriptions_table.put_item(Item=subscription)
    
    return {
        'statusCode': 201,
        'headers': get_cors_headers(),
        'body': json.dumps(subscription, cls=DecimalEncoder)
    }

def delete_subscription(subscriptions_table, subscription_id):
    response = subscriptions_table.delete_item(
        Key={'id': subscription_id},
        ReturnValues='ALL_OLD'
    )
    
    if 'Attributes' not in response:
        return error_response(404, 'Subscription not found')
    
    return {
        'statusCode': 204,
        'headers': get_cors_headers(),
        'body': ''
    }

def subscribe_person_to_project(subscriptions_table, project_id, person_id, event):
    body = json.loads(event.get('body', '{}'))
    subscription_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    subscription = {
        'id': subscription_id,
        'projectId': project_id,
        'personId': person_id,
        'status': 'active',
        'subscribedAt': now,
        'subscribedBy': body.get('subscribedBy', 'admin'),
        'notes': body.get('notes', '')
    }
    
    subscriptions_table.put_item(Item=subscription)
    
    return {
        'statusCode': 201,
        'headers': get_cors_headers(),
        'body': json.dumps(subscription, cls=DecimalEncoder)
    }

def unsubscribe_person_from_project(subscriptions_table, project_id, person_id):
    # Find the subscription
    response = subscriptions_table.query(
        IndexName='ProjectIndex',
        KeyConditionExpression='projectId = :projectId',
        ExpressionAttributeValues={':projectId': project_id}
    )
    
    subscription_to_delete = None
    for subscription in response.get('Items', []):
        if subscription['personId'] == person_id:
            subscription_to_delete = subscription
            break
    
    if not subscription_to_delete:
        return error_response(404, 'Subscription not found')
    
    subscriptions_table.delete_item(Key={'id': subscription_to_delete['id']})
    
    return {
        'statusCode': 204,
        'headers': get_cors_headers(),
        'body': ''
    }

def get_project_subscribers(subscriptions_table, people_table, project_id):
    # Get all subscriptions for this project
    response = subscriptions_table.query(
        IndexName='ProjectIndex',
        KeyConditionExpression='projectId = :projectId',
        ExpressionAttributeValues={':projectId': project_id}
    )
    
    subscribers = []
    for subscription in response.get('Items', []):
        # Get person details
        person_response = people_table.get_item(Key={'id': subscription['personId']})
        if 'Item' in person_response:
            subscriber = person_response['Item']
            subscriber['subscriptionId'] = subscription['id']
            subscriber['subscriptionStatus'] = subscription['status']
            subscriber['subscribedAt'] = subscription['subscribedAt']
            subscribers.append(subscriber)
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(subscribers, cls=DecimalEncoder)
    }

def get_admin_dashboard(people_table, projects_table, subscriptions_table):
    # Get counts
    people_response = people_table.scan(Select='COUNT')
    projects_response = projects_table.scan(Select='COUNT')
    subscriptions_response = subscriptions_table.scan(Select='COUNT')
    
    dashboard_data = {
        'totalPeople': people_response.get('Count', 0),
        'totalProjects': projects_response.get('Count', 0),
        'totalSubscriptions': subscriptions_response.get('Count', 0),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(dashboard_data, cls=DecimalEncoder)
    }
