from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
from datetime import datetime
import io
import requests
import traceback
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
import uuid
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="Media Sanitization Certificate Generator", 
    version="2.0.0",
    description="Generate NIST SP 800-88r2 compliant PDF certificates"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

print(f"🔑 Supabase URL: {SUPABASE_URL}")
print(f"🔑 Supabase Key: {'Set' if SUPABASE_KEY else 'Not Set'}")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("SUPABASE_URL and SUPABASE_KEY must be set in .env file")

# Supabase client
class SupabaseClient:
    def __init__(self, url: str, key: str):
        self.url = url.rstrip('/')
        self.key = key
        self.headers = {
            'apikey': key,
            'Authorization': f'Bearer {key}',
            'Content-Type': 'application/json'
        }
    
    def verify_user(self, token: str):
        """Verify user token and get user info"""
        headers = {
            'apikey': self.key,
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(f"{self.url}/auth/v1/user", headers=headers)
        print(f"🔐 User verification: {response.status_code}")
        
        if response.status_code == 200:
            return response.json()
        return None
    
    def upload_file(self, bucket: str, filename: str, file_data: bytes):
        """Upload file to storage"""
        upload_url = f"{self.url}/storage/v1/object/{bucket}/{filename}"
        headers = {
            'apikey': self.key,
            'Authorization': f'Bearer {self.key}',
            'Content-Type': 'application/pdf'
        }
        
        print(f"📤 Uploading: {filename}")
        response = requests.post(upload_url, data=file_data, headers=headers)
        print(f"📤 Upload status: {response.status_code}")
        return response
    
    def get_public_url(self, bucket: str, filename: str):
        """Get public URL for file"""
        return f"{self.url}/storage/v1/object/public/{bucket}/{filename}"
    
    def insert_record(self, table: str, data: dict):
        """Insert record into database"""
        insert_url = f"{self.url}/rest/v1/{table}"
        
        print(f"💾 Saving to database")
        response = requests.post(insert_url, json=data, headers=self.headers)
        print(f"💾 Save status: {response.status_code}")
        return response
    
    def select_records(self, table: str, filters: dict = None, limit: int = None, offset: int = None):
        """Select records from database"""
        select_url = f"{self.url}/rest/v1/{table}"
        
        params = {}
        
        if filters:
            for key, value in filters.items():
                params[f"{key}"] = f"eq.{value}"
        
        if limit:
            params['limit'] = limit
        
        if offset:
            params['offset'] = offset
        
        response = requests.get(select_url, params=params, headers=self.headers)
        return response

# Initialize Supabase client
supabase = SupabaseClient(SUPABASE_URL, SUPABASE_KEY)

# Response model
class CertificateResponse(BaseModel):
    certificate_id: str
    pdf_url: str
    created_at: str
    user_id: str
    device_model: str
    message: str

def generate_certificate_pdf(data: dict, certificate_id: str, user_email: str) -> bytes:
    """Generate professional single-page certificate"""
    
    print("📄 Starting PDF generation...")
    buffer = io.BytesIO()
    
    # Setup document
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=30
    )
    
    # Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=22,
        textColor=colors.HexColor('#000000'),
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    section_heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor('#000000'),
        spaceAfter=8,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    label_style = ParagraphStyle(
        'Label',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#000000'),
        fontName='Helvetica-Bold',
        leading=12
    )
    
    value_style = ParagraphStyle(
        'Value',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#000000'),
        fontName='Helvetica',
        leading=12
    )
    
    success_style = ParagraphStyle(
        'Success',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#008000'),
        fontName='Helvetica',
        leading=12
    )
    
    # Helper function
    def get_value(obj, key, default='N/A'):
        if isinstance(obj, dict):
            val = obj.get(key, default)
            return str(val) if val else default
        return default
    
    # Build content
    story = []
    
    # Title
    story.append(Paragraph("Media Sanitization Certificate", title_style))
    story.append(Spacer(1, 10))
    
    # Horizontal line
    line_table = Table([['']], colWidths=[7*inch])
    line_table.setStyle(TableStyle([
        ('LINEABOVE', (0, 0), (-1, 0), 2, colors.HexColor('#000000')),
    ]))
    story.append(line_table)
    story.append(Spacer(1, 15))
    
    # Extract data
    cert_metadata = data.get('certificate_metadata', {})
    tool_info = data.get('tool_information', {})
    sanitization_event = data.get('sanitization_event', {})
    media_info = data.get('media_information', {})
    sanitization_details = data.get('sanitization_details', {})
    host_info = data.get('host_system_information', {})
    compliance_info = data.get('compliance_information', {})
    
    # Certificate Information
    story.append(Paragraph("Certificate Information", section_heading_style))
    cert_info_data = [
        [Paragraph('Certificate ID:', label_style), 
         Paragraph(get_value(cert_metadata, 'certificate_id', certificate_id), value_style),
         Paragraph('Generated Timestamp:', label_style),
         Paragraph(get_value(cert_metadata, 'generated_timestamp'), value_style)],
        [Paragraph('Version:', label_style),
         Paragraph(get_value(cert_metadata, 'version'), value_style),
         Paragraph('NIST Reference:', label_style),
         Paragraph(get_value(cert_metadata, 'nist_reference'), value_style)]
    ]
    
    cert_info_table = Table(cert_info_data, colWidths=[1.3*inch, 2*inch, 1.3*inch, 2*inch])
    cert_info_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(cert_info_table)
    story.append(Spacer(1, 12))
    
    # Tool Information
    story.append(Paragraph("Tool Information", section_heading_style))
    tool_data = [
        [Paragraph('Name:', label_style),
         Paragraph(get_value(tool_info, 'name'), value_style),
         Paragraph('Version:', label_style),
         Paragraph(get_value(tool_info, 'version'), value_style)],
        [Paragraph('Method:', label_style),
         Paragraph(get_value(tool_info, 'method'), value_style),
         Paragraph('Technique:', label_style),
         Paragraph(get_value(tool_info, 'technique'), value_style)],
        [Paragraph('Verification Method:', label_style),
         Paragraph(get_value(tool_info, 'verification_method'), value_style),
         Paragraph('', label_style),
         Paragraph('', value_style)]
    ]
    
    tool_table = Table(tool_data, colWidths=[1.3*inch, 2*inch, 1.3*inch, 2*inch])
    tool_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(tool_table)
    story.append(Spacer(1, 12))
    
    # Sanitization Event
    story.append(Paragraph("Sanitization Event", section_heading_style))
    operator = sanitization_event.get('operator', {})
    event_data = [
        [Paragraph('Timestamp:', label_style),
         Paragraph(get_value(sanitization_event, 'timestamp'), value_style),
         Paragraph('Status:', label_style),
         Paragraph(get_value(sanitization_event, 'status'), success_style)],
        [Paragraph('System User:', label_style),
         Paragraph(get_value(operator, 'system_user'), value_style),
         Paragraph('Hostname:', label_style),
         Paragraph(get_value(operator, 'hostname'), value_style)]
    ]
    
    event_table = Table(event_data, colWidths=[1.3*inch, 2*inch, 1.3*inch, 2*inch])
    event_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(event_table)
    story.append(Spacer(1, 12))
    
    # Media Information
    story.append(Paragraph("Media Information", section_heading_style))
    media_data = [
        [Paragraph('Device Path:', label_style),
         Paragraph(get_value(media_info, 'device_path'), value_style),
         Paragraph('Manufacturer:', label_style),
         Paragraph(get_value(media_info, 'manufacturer'), value_style)],
        [Paragraph('Model:', label_style),
         Paragraph(get_value(media_info, 'model'), value_style),
         Paragraph('Serial Number:', label_style),
         Paragraph(get_value(media_info, 'serial_number'), value_style)],
        [Paragraph('Firmware Version:', label_style),
         Paragraph(get_value(media_info, 'firmware_version'), value_style),
         Paragraph('Interface Type:', label_style),
         Paragraph(get_value(media_info, 'interface_type'), value_style)],
        [Paragraph('Media Type:', label_style),
         Paragraph(get_value(media_info, 'media_type'), value_style),
         Paragraph('Device Type:', label_style),
         Paragraph(get_value(media_info, 'device_type'), value_style)],
        [Paragraph('Capacity (GB):', label_style),
         Paragraph(get_value(media_info, 'capacity_gb'), value_style),
         Paragraph('Capacity (Bytes):', label_style),
         Paragraph(get_value(media_info, 'capacity_bytes'), value_style)],
        [Paragraph('Pre-Sanitization Class:', label_style),
         Paragraph(get_value(media_info, 'pre_sanitization_classification'), value_style),
         Paragraph('Post-Sanitization Class:', label_style),
         Paragraph(get_value(media_info, 'post_sanitization_classification'), value_style)]
    ]
    
    media_table = Table(media_data, colWidths=[1.3*inch, 2*inch, 1.3*inch, 2*inch])
    media_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(media_table)
    story.append(Spacer(1, 12))
    
    # Sanitization Details
    story.append(Paragraph("Sanitization Details", section_heading_style))
    passes = sanitization_details.get('passes_performed', [])
    passes_count = str(len(passes)) if passes else 'N/A'
    
    san_det_data = [
        [Paragraph('Passes Performed:', label_style),
         Paragraph(passes_count, value_style),
         Paragraph('Verification Status:', label_style),
         Paragraph(get_value(sanitization_details, 'verification_status'), success_style)],
        [Paragraph('Verification Details:', label_style),
         Paragraph(get_value(sanitization_details, 'verification_details'), value_style),
         Paragraph('', label_style),
         Paragraph('', value_style)]
    ]
    
    san_det_table = Table(san_det_data, colWidths=[1.3*inch, 2*inch, 1.3*inch, 2*inch])
    san_det_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(san_det_table)
    story.append(Spacer(1, 12))
    
    # Host System Information
    story.append(Paragraph("Host System Information", section_heading_style))
    tools_used = host_info.get('tools_used', [])
    tools_str = ', '.join(tools_used) if tools_used else 'N/A'
    
    host_data = [
        [Paragraph('Hostname:', label_style),
         Paragraph(get_value(host_info, 'hostname'), value_style),
         Paragraph('Operating System:', label_style),
         Paragraph(get_value(host_info, 'operating_system'), value_style)],
        [Paragraph('Kernel Version:', label_style),
         Paragraph(get_value(host_info, 'kernel_version'), value_style),
         Paragraph('Architecture:', label_style),
         Paragraph(get_value(host_info, 'architecture'), value_style)],
        [Paragraph('System Manufacturer:', label_style),
         Paragraph(get_value(host_info, 'system_manufacturer'), value_style),
         Paragraph('System Model:', label_style),
         Paragraph(get_value(host_info, 'system_model'), value_style)],
        [Paragraph('System Serial:', label_style),
         Paragraph(get_value(host_info, 'system_serial'), value_style),
         Paragraph('Execution Environment:', label_style),
         Paragraph(get_value(host_info, 'execution_environment'), value_style)],
        [Paragraph('Tools Used:', label_style),
         Paragraph(tools_str, value_style),
         Paragraph('', label_style),
         Paragraph('', value_style)]
    ]
    
    host_table = Table(host_data, colWidths=[1.3*inch, 2*inch, 1.3*inch, 2*inch])
    host_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(host_table)
    story.append(Spacer(1, 12))
    
    # Compliance Information
    story.append(Paragraph("Compliance Information", section_heading_style))
    comp_data = [
        [Paragraph('Standard:', label_style),
         Paragraph(get_value(compliance_info, 'standard'), value_style),
         Paragraph('Sanitization Method:', label_style),
         Paragraph(get_value(compliance_info, 'sanitization_method'), value_style)],
        [Paragraph('Residual Risk Assessment:', label_style),
         Paragraph(get_value(compliance_info, 'residual_risk_assessment'), value_style),
         Paragraph('Recommended Follow-up:', label_style),
         Paragraph(get_value(compliance_info, 'recommended_follow_up'), value_style)]
    ]
    
    comp_table = Table(comp_data, colWidths=[1.3*inch, 2*inch, 1.3*inch, 2*inch])
    comp_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(comp_table)
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    print("📄 PDF generation completed!")
    return buffer.getvalue()

@app.post("/generate-certificate", response_model=CertificateResponse)
async def generate_certificate(
    request: Request,
    authorization: str = Header(None)
):
    """Generate certificate from JSON data"""
    
    try:
        # Verify authentication
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
        
        token = authorization.replace("Bearer ", "")
        
        # Verify user
        user_info = supabase.verify_user(token)
        if not user_info:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        
        user_id = user_info["id"]
        user_email = user_info.get("email", "unknown@example.com")
        
        # Get JSON data
        data = await request.json()
        
        print(f"🚀 Starting certificate generation for: {user_email}")
        print(f"📋 Received data sections: {list(data.keys())}")
        
        # Generate certificate ID
        certificate_id = str(uuid.uuid4())
        
        # Generate PDF
        pdf_bytes = generate_certificate_pdf(data, certificate_id, user_email)
        print(f"📄 PDF size: {len(pdf_bytes)} bytes")
        
        # Get device model
        device_model = (
            data.get('model') or 
            (data.get('media_information', {}).get('model')) or 
            'Unknown_Device'
        )
        
        safe_model = device_model.replace(" ", "_").replace("/", "_")
        filename = f"cert_{user_id}_{safe_model}_{certificate_id}.pdf"
        
        # Upload to storage
        print("📤 Uploading to storage...")
        upload_response = supabase.upload_file("certificates", filename, pdf_bytes)
        
        if upload_response.status_code not in [200, 201]:
            raise HTTPException(status_code=500, detail=f"Upload failed: {upload_response.text}")
        
        # Get public URL
        pdf_url = supabase.get_public_url("certificates", filename)
        
        # Prepare database record
        manufacturer = (
            data.get('manufacturer') or 
            (data.get('media_information', {}).get('manufacturer')) or 
            'Unknown'
        )
        
        serial_number = (
            data.get('serial_number') or 
            (data.get('media_information', {}).get('serial_number')) or 
            'Unknown'
        )
        
        certificate_data = {
            "certificate_id": certificate_id,
            "user_id": user_id,
            "user_email": user_email,
            "manufacturer": manufacturer,
            "model": device_model,
            "serial_number": serial_number,
            "property_number": data.get('property_number'),
            "media_type": data.get('media_type') or data.get('media_information', {}).get('media_type'),
            "media_source": data.get('media_source'),
            "pre_sanitization_confidentiality": data.get('pre_sanitization_confidentiality'),
            "sanitization_method": data.get('sanitization_method') or data.get('tool_information', {}).get('method'),
            "sanitization_technique": data.get('sanitization_technique') or data.get('tool_information', {}).get('technique'),
            "tool_used": data.get('tool_used') or data.get('tool_information', {}).get('name'),
            "verification_method": data.get('verification_method') or data.get('tool_information', {}).get('verification_method'),
            "post_sanitization_confidentiality": data.get('post_sanitization_confidentiality'),
            "post_sanitization_destination": data.get('post_sanitization_destination'),
            "certificate_metadata": data.get('certificate_metadata'),
            "tool_information": data.get('tool_information'),
            "sanitization_event": data.get('sanitization_event'),
            "media_information": data.get('media_information'),
            "sanitization_details": data.get('sanitization_details'),
            "host_system_information": data.get('host_system_information'),
            "compliance_information": data.get('compliance_information'),
            "pdf_url": pdf_url,
            "created_at": datetime.now().isoformat()
        }
        
        # Save to database
        print("💾 Saving to database...")
        db_response = supabase.insert_record("certificates", certificate_data)
        
        if db_response.status_code not in [200, 201]:
            raise HTTPException(status_code=500, detail=f"Database save failed: {db_response.text}")
        
        print("✅ Certificate generated successfully!")
        
        return CertificateResponse(
            certificate_id=certificate_id,
            pdf_url=pdf_url,
            created_at=datetime.now().isoformat(),
            user_id=user_id,
            device_model=device_model,
            message="Certificate generated successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        print(f"🔍 Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/my-certificates")
async def get_my_certificates(authorization: str = Header(None), limit: int = 10, offset: int = 0):
    """Get all certificates for authenticated user"""
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing authorization header")
        
        token = authorization.replace("Bearer ", "")
        user_info = supabase.verify_user(token)
        if not user_info:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_id = user_info["id"]
        
        response = supabase.select_records("certificates", {"user_id": user_id}, limit=limit, offset=offset)
        
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Database error")
        
        data = response.json()
        
        return {
            "user_id": user_id,
            "certificates": data,
            "count": len(data)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/certificates-by-device/{model}")
async def get_certificates_by_device(model: str, authorization: str = Header(None)):
    """Get certificates for specific device model"""
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing authorization header")
        
        token = authorization.replace("Bearer ", "")
        user_info = supabase.verify_user(token)
        if not user_info:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_id = user_info["id"]
        
        response = supabase.select_records("certificates", {"user_id": user_id, "model": model})
        
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Database error")
        
        data = response.json()
        
        if not data:
            raise HTTPException(status_code=404, detail="No certificates found")
        
        return {
            "device_model": model,
            "manufacturer": data[0].get('manufacturer', 'Unknown'),
            "total_certificates": len(data),
            "certificates": data
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Media Sanitization Certificate API",
        "version": "2.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/user-info")
async def get_user_info(authorization: str = Header(None)):
    """Get current user information"""
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing authorization header")
        
        token = authorization.replace("Bearer ", "")
        user_info = supabase.verify_user(token)
        if not user_info:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return {
            "user_id": user_info["id"],
            "email": user_info.get("email"),
            "authenticated": True
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🚀 Media Sanitization Certificate Generator")
    print("=" * 60)
    print(f"📍 Server: http://localhost:8000")
    print(f"📖 API Docs: http://localhost:8000/docs")
    print(f"🔐 Authentication: Required")
    print(f"📄 PDF Format: Professional Single Page")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)