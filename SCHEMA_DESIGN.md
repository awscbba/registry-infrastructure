# Database Schema Design - Project Management

## Current Tables

### PeopleTable
- **PK**: `id` (string) - Person UUID
- `firstName`, `lastName`, `email`, `phone`, `dateOfBirth`
- `address` (object)
- `createdAt`, `updatedAt`

## New Tables

### ProjectsTable
- **PK**: `id` (string) - Project UUID
- `name` (string) - Project name
- `description` (string) - Project description
- `status` (string) - active | inactive | completed
- `createdBy` (string) - Admin user who created it
- `maxParticipants` (number) - Optional limit
- `startDate` (string) - ISO date
- `endDate` (string) - ISO date (optional)
- `createdAt`, `updatedAt`

### SubscriptionsTable
- **PK**: `id` (string) - Subscription UUID
- **GSI1PK**: `projectId` (string) - For querying by project
- **GSI2PK**: `personId` (string) - For querying by person
- `projectId` (string) - Reference to project
- `personId` (string) - Reference to person
- `status` (string) - active | inactive | pending
- `subscribedAt` (string) - ISO date
- `subscribedBy` (string) - Admin who added subscription
- `notes` (string) - Optional notes

## API Endpoints

### Projects
- `GET /projects` - List all projects
- `POST /projects` - Create new project
- `GET /projects/{id}` - Get project details
- `PUT /projects/{id}` - Update project
- `DELETE /projects/{id}` - Delete project
- `GET /projects/{id}/subscribers` - Get project subscribers

### Subscriptions
- `GET /subscriptions` - List all subscriptions
- `POST /subscriptions` - Create subscription
- `DELETE /subscriptions/{id}` - Remove subscription
- `GET /people/{id}/subscriptions` - Get person's subscriptions
- `POST /projects/{projectId}/subscribe/{personId}` - Subscribe person to project
- `DELETE /projects/{projectId}/unsubscribe/{personId}` - Unsubscribe person

### Admin
- `GET /admin/dashboard` - Admin dashboard data
- `GET /admin/projects` - Admin project management
- `GET /admin/subscriptions` - Admin subscription management

## Frontend Pages

### User Pages
- `/` - People Registry (existing)
- `/projects` - View available projects
- `/my-subscriptions` - User's project subscriptions

### Admin Pages
- `/admin` - Admin dashboard
- `/admin/projects` - Project management
- `/admin/subscriptions` - Subscription management
- `/admin/people` - People management (enhanced)

## Implementation Strategy

1. **Phase 1**: Backend API (Projects + Subscriptions)
2. **Phase 2**: Admin Frontend Pages
3. **Phase 3**: User Frontend Pages
4. **Phase 4**: Integration & Testing
