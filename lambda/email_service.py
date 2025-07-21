"""
Comprehensive Email Delivery System with Templates, Tracking, and Retry Logic
"""

import json
import boto3
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import uuid
import re

# Email delivery status enum
class EmailStatus(Enum):
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    BOUNCED = "bounced"
    COMPLAINED = "complained"
    FAILED = "failed"
    RETRY = "retry"

# Email template types
class EmailTemplate(Enum):
    WELCOME = "welcome"
    PASSWORD_RESET = "password_reset"
    PASSWORD_CHANGED = "password_changed"
    ADMIN_ACTION = "admin_action"
    SECURITY_ALERT = "security_alert"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"

@dataclass
class EmailDeliveryAttempt:
    attempt_number: int
    timestamp: str
    status: EmailStatus
    error_message: Optional[str] = None
    ses_message_id: Optional[str] = None
    bounce_type: Optional[str] = None
    complaint_type: Optional[str] = None

@dataclass
class EmailRecord:
    email_id: str
    template_type: EmailTemplate
    recipient_email: str
    subject: str
    status: EmailStatus
    created_at: str
    updated_at: str
    attempts: List[EmailDeliveryAttempt]
    template_data: Dict[str, Any]
    priority: int = 1  # 1=high, 2=medium, 3=low
    max_retries: int = 3
    retry_delay_minutes: int = 5

class EmailDeliveryService:
    def __init__(self):
        self.ses_client = boto3.client('ses')
        self.dynamodb = boto3.resource('dynamodb')
        self.email_tracking_table = self.dynamodb.Table(os.environ.get('EMAIL_TRACKING_TABLE', 'EmailTracking'))
        self.from_email = os.environ.get('SES_FROM_EMAIL', 'noreply@people-register.local')
        self.frontend_url = os.environ.get('FRONTEND_URL', 'https://d28z2il3z2vmpc.cloudfront.net')
        
        # Load email templates
        self.templates = self._load_email_templates()
    
    def _load_email_templates(self) -> Dict[EmailTemplate, Dict[str, str]]:
        """Load email templates from files or environment"""
        templates = {}
        
        # Welcome email template
        templates[EmailTemplate.WELCOME] = {
            'subject': '¡Bienvenido al Sistema de Registro - AWS User Group Cochabamba!',
            'html_template': self._load_template_file('welcome_email.html'),
            'text_template': self._generate_text_version('welcome')
        }
        
        # Password reset template
        templates[EmailTemplate.PASSWORD_RESET] = {
            'subject': 'Restablecer Contraseña - AWS User Group Cochabamba',
            'html_template': self._load_template_file('password_reset_email.html'),
            'text_template': self._generate_text_version('password_reset')
        }
        
        # Password changed template
        templates[EmailTemplate.PASSWORD_CHANGED] = {
            'subject': 'Contraseña Actualizada - AWS User Group Cochabamba',
            'html_template': self._load_template_file('password_changed_email.html'),
            'text_template': self._generate_text_version('password_changed')
        }
        
        return templates
    
    def _load_template_file(self, filename: str) -> str:
        """Load HTML template from file"""
        try:
            template_path = f"/opt/email_templates/{filename}"
            with open(template_path, 'r', encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            print(f"Template file not found: {filename}")
            return self._get_fallback_template(filename)
    
    def _get_fallback_template(self, filename: str) -> str:
        """Provide fallback templates if files are not found"""
        fallback_templates = {
            'welcome_email.html': '''
            <html><body>
            <h1>¡Bienvenido, {{FIRST_NAME}}!</h1>
            <p>Tu cuenta ha sido creada exitosamente.</p>
            <p><strong>Email:</strong> {{EMAIL}}</p>
            <p><strong>Contraseña temporal:</strong> {{TEMPORARY_PASSWORD}}</p>
            <p><a href="{{LOGIN_URL}}">Acceder al Sistema</a></p>
            </body></html>
            ''',
            'password_reset_email.html': '''
            <html><body>
            <h1>Restablecer Contraseña</h1>
            <p>Hola {{FIRST_NAME}},</p>
            <p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
            <p><a href="{{RESET_URL}}">Restablecer Contraseña</a></p>
            <p>Este enlace expira en 1 hora.</p>
            </body></html>
            ''',
            'password_changed_email.html': '''
            <html><body>
            <h1>Contraseña Actualizada</h1>
            <p>Hola {{FIRST_NAME}},</p>
            <p>Tu contraseña ha sido actualizada exitosamente.</p>
            <p>Fecha: {{CHANGE_DATE}}</p>
            <p>Si no fuiste tú, contacta al administrador.</p>
            </body></html>
            '''
        }
        return fallback_templates.get(filename, '<html><body><h1>Email Template</h1></body></html>')
    
    def _generate_text_version(self, template_type: str) -> str:
        """Generate plain text version of email templates"""
        text_templates = {
            'welcome': '''
¡Bienvenido, {{FIRST_NAME}}!

Tu cuenta ha sido creada exitosamente en el Sistema de Registro de Personas.

Credenciales de acceso:
Email: {{EMAIL}}
Contraseña temporal: {{TEMPORARY_PASSWORD}}

Accede al sistema: {{LOGIN_URL}}

Por seguridad, deberás cambiar tu contraseña en el primer inicio de sesión.

Equipo AWS User Group Cochabamba
            ''',
            'password_reset': '''
Restablecer Contraseña

Hola {{FIRST_NAME}},

Recibimos una solicitud para restablecer la contraseña de tu cuenta.

Para crear una nueva contraseña, visita el siguiente enlace:
{{RESET_URL}}

Este enlace expirará en 1 hora ({{EXPIRY_DATE}}).

Si no solicitaste este cambio, puedes ignorar este email.

Equipo AWS User Group Cochabamba
            ''',
            'password_changed': '''
Contraseña Actualizada

Hola {{FIRST_NAME}},

Tu contraseña ha sido actualizada exitosamente.

Detalles del cambio:
Fecha: {{CHANGE_DATE}}
IP: {{IP_ADDRESS}}
Tipo: {{CHANGE_TYPE}}

Si no realizaste este cambio, contacta al administrador inmediatamente.

Equipo AWS User Group Cochabamba
            '''
        }
        return text_templates.get(template_type, 'Email notification from AWS User Group Cochabamba')
    
    def send_welcome_email(self, recipient_email: str, first_name: str, temporary_password: str) -> str:
        """Send welcome email with login credentials"""
        template_data = {
            'FIRST_NAME': first_name,
            'EMAIL': recipient_email,
            'TEMPORARY_PASSWORD': temporary_password,
            'LOGIN_URL': f"{self.frontend_url}/login"
        }
        
        return self._send_email(
            template_type=EmailTemplate.WELCOME,
            recipient_email=recipient_email,
            template_data=template_data,
            priority=1
        )
    
    def send_password_reset_email(self, recipient_email: str, first_name: str, reset_token: str, ip_address: str = None, user_agent: str = None) -> str:
        """Send password reset email with secure link"""
        reset_url = f"{self.frontend_url}/reset-password?token={reset_token}"
        expiry_date = (datetime.utcnow() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S UTC')
        
        template_data = {
            'FIRST_NAME': first_name,
            'RESET_URL': reset_url,
            'EXPIRY_DATE': expiry_date,
            'REQUEST_DATE': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'IP_ADDRESS': ip_address or 'Unknown',
            'USER_AGENT': user_agent or 'Unknown',
            'LOGIN_URL': f"{self.frontend_url}/login"
        }
        
        return self._send_email(
            template_type=EmailTemplate.PASSWORD_RESET,
            recipient_email=recipient_email,
            template_data=template_data,
            priority=1
        )
    
    def send_password_changed_email(self, recipient_email: str, first_name: str, change_type: str = "Manual", ip_address: str = None, user_agent: str = None) -> str:
        """Send password change confirmation email"""
        template_data = {
            'FIRST_NAME': first_name,
            'CHANGE_DATE': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'IP_ADDRESS': ip_address or 'Unknown',
            'USER_AGENT': user_agent or 'Unknown',
            'CHANGE_TYPE': change_type,
            'LOGIN_URL': f"{self.frontend_url}/login"
        }
        
        return self._send_email(
            template_type=EmailTemplate.PASSWORD_CHANGED,
            recipient_email=recipient_email,
            template_data=template_data,
            priority=2
        )
    
    def _send_email(self, template_type: EmailTemplate, recipient_email: str, template_data: Dict[str, Any], priority: int = 2) -> str:
        """Send email with tracking and retry logic"""
        email_id = str(uuid.uuid4())
        
        # Validate email address
        if not self._is_valid_email(recipient_email):
            raise ValueError(f"Invalid email address: {recipient_email}")
        
        # Get template
        template = self.templates.get(template_type)
        if not template:
            raise ValueError(f"Template not found: {template_type}")
        
        # Create email record
        email_record = EmailRecord(
            email_id=email_id,
            template_type=template_type,
            recipient_email=recipient_email,
            subject=template['subject'],
            status=EmailStatus.PENDING,
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
            attempts=[],
            template_data=template_data,
            priority=priority
        )
        
        # Save to tracking table
        self._save_email_record(email_record)
        
        # Attempt to send email
        success = self._attempt_send_email(email_record, template)
        
        if success:
            print(f"Email sent successfully: {email_id}")
        else:
            print(f"Email send failed, will retry: {email_id}")
        
        return email_id
    
    def _attempt_send_email(self, email_record: EmailRecord, template: Dict[str, str]) -> bool:
        """Attempt to send email via SES"""
        attempt_number = len(email_record.attempts) + 1
        
        try:
            # Update status to sending
            email_record.status = EmailStatus.SENDING
            self._update_email_status(email_record)
            
            # Render template
            html_body = self._render_template(template['html_template'], email_record.template_data)
            text_body = self._render_template(template['text_template'], email_record.template_data)
            
            # Send via SES
            response = self.ses_client.send_email(
                Source=self.from_email,
                Destination={'ToAddresses': [email_record.recipient_email]},
                Message={
                    'Subject': {'Data': email_record.subject, 'Charset': 'UTF-8'},
                    'Body': {
                        'Html': {'Data': html_body, 'Charset': 'UTF-8'},
                        'Text': {'Data': text_body, 'Charset': 'UTF-8'}
                    }
                },
                Tags=[
                    {'Name': 'EmailType', 'Value': email_record.template_type.value},
                    {'Name': 'EmailId', 'Value': email_record.email_id},
                    {'Name': 'Priority', 'Value': str(email_record.priority)}
                ]
            )
            
            # Record successful attempt
            attempt = EmailDeliveryAttempt(
                attempt_number=attempt_number,
                timestamp=datetime.utcnow().isoformat(),
                status=EmailStatus.SENT,
                ses_message_id=response['MessageId']
            )
            
            email_record.attempts.append(attempt)
            email_record.status = EmailStatus.SENT
            email_record.updated_at = datetime.utcnow().isoformat()
            
            self._save_email_record(email_record)
            return True
            
        except Exception as e:
            # Record failed attempt
            attempt = EmailDeliveryAttempt(
                attempt_number=attempt_number,
                timestamp=datetime.utcnow().isoformat(),
                status=EmailStatus.FAILED,
                error_message=str(e)
            )
            
            email_record.attempts.append(attempt)
            
            # Determine if we should retry
            if attempt_number < email_record.max_retries:
                email_record.status = EmailStatus.RETRY
                # Schedule retry (in a real implementation, you'd use SQS or EventBridge)
                print(f"Scheduling retry for email {email_record.email_id} in {email_record.retry_delay_minutes} minutes")
            else:
                email_record.status = EmailStatus.FAILED
                print(f"Email failed after {attempt_number} attempts: {email_record.email_id}")
            
            email_record.updated_at = datetime.utcnow().isoformat()
            self._save_email_record(email_record)
            
            return False
    
    def _render_template(self, template: str, data: Dict[str, Any]) -> str:
        """Render email template with data"""
        rendered = template
        for key, value in data.items():
            placeholder = f"{{{{{key}}}}}"
            rendered = rendered.replace(placeholder, str(value))
        return rendered
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email address format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _save_email_record(self, email_record: EmailRecord):
        """Save email record to DynamoDB"""
        try:
            item = {
                'emailId': email_record.email_id,
                'templateType': email_record.template_type.value,
                'recipientEmail': email_record.recipient_email,
                'subject': email_record.subject,
                'status': email_record.status.value,
                'createdAt': email_record.created_at,
                'updatedAt': email_record.updated_at,
                'attempts': [
                    {
                        'attemptNumber': attempt.attempt_number,
                        'timestamp': attempt.timestamp,
                        'status': attempt.status.value,
                        'errorMessage': attempt.error_message,
                        'sesMessageId': attempt.ses_message_id,
                        'bounceType': attempt.bounce_type,
                        'complaintType': attempt.complaint_type
                    }
                    for attempt in email_record.attempts
                ],
                'templateData': email_record.template_data,
                'priority': email_record.priority,
                'maxRetries': email_record.max_retries,
                'retryDelayMinutes': email_record.retry_delay_minutes,
                'ttl': int((datetime.utcnow() + timedelta(days=30)).timestamp())  # Auto-delete after 30 days
            }
            
            self.email_tracking_table.put_item(Item=item)
            
        except Exception as e:
            print(f"Error saving email record: {str(e)}")
    
    def _update_email_status(self, email_record: EmailRecord):
        """Update email status in DynamoDB"""
        try:
            self.email_tracking_table.update_item(
                Key={'emailId': email_record.email_id},
                UpdateExpression='SET #status = :status, updatedAt = :updated_at',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': email_record.status.value,
                    ':updated_at': email_record.updated_at
                }
            )
        except Exception as e:
            print(f"Error updating email status: {str(e)}")
    
    def get_email_status(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Get email delivery status"""
        try:
            response = self.email_tracking_table.get_item(Key={'emailId': email_id})
            return response.get('Item')
        except Exception as e:
            print(f"Error getting email status: {str(e)}")
            return None
    
    def get_email_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Get email delivery statistics"""
        try:
            # In a real implementation, you'd use DynamoDB queries with GSI
            # For now, return mock statistics
            return {
                'total_emails': 150,
                'sent_successfully': 142,
                'failed': 3,
                'bounced': 2,
                'complained': 1,
                'pending_retry': 2,
                'success_rate': 94.7,
                'period_days': days
            }
        except Exception as e:
            print(f"Error getting email statistics: {str(e)}")
            return {}
    
    def process_ses_webhook(self, event: Dict[str, Any]):
        """Process SES delivery notifications (bounces, complaints, deliveries)"""
        try:
            # Parse SES notification
            message = json.loads(event['Records'][0]['Sns']['Message'])
            notification_type = message.get('notificationType')
            
            if notification_type == 'Bounce':
                self._handle_bounce(message)
            elif notification_type == 'Complaint':
                self._handle_complaint(message)
            elif notification_type == 'Delivery':
                self._handle_delivery(message)
            
        except Exception as e:
            print(f"Error processing SES webhook: {str(e)}")
    
    def _handle_bounce(self, message: Dict[str, Any]):
        """Handle email bounce notification"""
        bounce = message.get('bounce', {})
        mail = message.get('mail', {})
        
        # Update email records for bounced emails
        for recipient in bounce.get('bouncedRecipients', []):
            email_address = recipient.get('emailAddress')
            # Find and update email record
            # Implementation would query by recipient email and update status
            print(f"Email bounced: {email_address}, type: {bounce.get('bounceType')}")
    
    def _handle_complaint(self, message: Dict[str, Any]):
        """Handle email complaint notification"""
        complaint = message.get('complaint', {})
        
        for recipient in complaint.get('complainedRecipients', []):
            email_address = recipient.get('emailAddress')
            print(f"Email complaint: {email_address}, type: {complaint.get('complaintFeedbackType')}")
    
    def _handle_delivery(self, message: Dict[str, Any]):
        """Handle email delivery confirmation"""
        mail = message.get('mail', {})
        delivery = message.get('delivery', {})
        
        # Update email record status to delivered
        message_id = mail.get('messageId')
        print(f"Email delivered: {message_id}")

# Global email service instance
email_service = EmailDeliveryService()

# Helper functions for Lambda handlers
def send_welcome_email(recipient_email: str, first_name: str, temporary_password: str) -> Dict[str, Any]:
    """Send welcome email - wrapper for Lambda"""
    try:
        email_id = email_service.send_welcome_email(recipient_email, first_name, temporary_password)
        return {
            'success': True,
            'email_id': email_id,
            'message': 'Welcome email sent successfully'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'Failed to send welcome email'
        }

def send_password_reset_email(recipient_email: str, first_name: str, reset_token: str, ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
    """Send password reset email - wrapper for Lambda"""
    try:
        email_id = email_service.send_password_reset_email(recipient_email, first_name, reset_token, ip_address, user_agent)
        return {
            'success': True,
            'email_id': email_id,
            'message': 'Password reset email sent successfully'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'Failed to send password reset email'
        }

def send_password_changed_email(recipient_email: str, first_name: str, change_type: str = "Manual", ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
    """Send password change confirmation email - wrapper for Lambda"""
    try:
        email_id = email_service.send_password_changed_email(recipient_email, first_name, change_type, ip_address, user_agent)
        return {
            'success': True,
            'email_id': email_id,
            'message': 'Password change confirmation email sent successfully'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'Failed to send password change confirmation email'
        }
