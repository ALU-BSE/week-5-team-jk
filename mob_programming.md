# JWT Authentication Mob Programming Activity
## SafeBoda API with JWT & Testing (90 Minutes)

---

## Activity Overview

**Duration**: 1.5 hours (90 minutes)  
**Format**: Mob Programming (Breakout Rooms)  
**Group Size**: 3-5 students per group  
**Rotation Time**: 10 minutes per driver  
**Platform**: GitHub Classroom + Codespaces + Google Meet

---

## Learning Objectives

By the end of this activity, students will be able to:

1. **Implement JWT authentication** in a Django REST Framework application
2. **Build RESTful API endpoints** for user registration and authentication
3. **Test APIs** using Postman with automated test scripts
4. **Collaborate effectively** using mob programming methodology
5. **Apply secure authentication practices**

---

## Technical Stack

- **Backend**: Django 5.2.6 + Django REST Framework
- **Authentication**: JWT (Simple JWT)
- **Documentation**: drf-spectacular (basic setup only)
- **Testing**: Postman
- **Environment**: GitHub Codespaces

---

## Mob Programming Roles

### **Driver** (10 minutes per rotation)
- Controls the keyboard and types code
- Follows navigator's instructions
- Asks clarifying questions
- Focuses on implementation

### **Navigators** (All other team members)
- Guide the driver with strategic decisions
- Discuss approaches and solutions
- Look up documentation
- One navigator acts as **Lead Navigator** (rotates each round)

### **Lead Navigator** (Changes each rotation)
- Primary voice guiding the driver
- Makes final decisions on approach
- Manages time and ensures progress

---

## Activity Timeline

### **Setup Phase** (15 minutes - No rotation)
All team members work together

### **Development Phase** (60 minutes)
**6 rotations** × 10 minutes each

| Rotation | Duration | Task Focus |
|----------|----------|------------|
| 1 | 10 min | Install packages, configure JWT, create serializers |
| 2 | 10 min | Build registration endpoint |
| 3 | 10 min | Build login endpoint & test |
| 4 | 10 min | Create protected profile endpoint |
| 5 | 10 min | Configure URLs & basic documentation |
| 6 | 10 min | Create Postman collection & test |

### **Wrap-up Phase** (15 minutes - No rotation)
Team testing and documentation

---

## Pre-Activity Preparation

### **For Instructors:**
1. Create GitHub Classroom assignment from `pelino250/safeboda`
2. Enable Codespaces
3. Set up Google Meet with breakout rooms (3-5 per room)
4. Share activity guide and quick reference

### **For Students:**
1. Accept GitHub Classroom invitation
2. Launch Codespace from repository
3. Join assigned Google Meet breakout room
4. Have Postman ready (desktop or web)

---

## Activity Instructions

## PHASE 1: Setup & Configuration (15 minutes)

**All team members collaborate - No rotation yet**

### Step 1: Environment Setup (5 minutes)

```bash
# In Codespace terminal
python -m venv venv
source venv/bin/activate

# Install existing dependencies
pip install -r requirements.txt
```

### Step 2: Install Required Packages (3 minutes)

```bash
# Install JWT, DRF, and documentation packages
pip install djangorestframework djangorestframework-simplejwt drf-spectacular

# Update requirements
pip freeze > requirements.txt
```

### Step 3: Configure Django Settings (7 minutes)

**Add to `safeboda/settings.py`:**

```python
INSTALLED_APPS = [
    # ... existing apps ...
    'rest_framework',
    'rest_framework_simplejwt',
    'drf_spectacular',
]

# REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# JWT Settings
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

# API Documentation Settings
SPECTACULAR_SETTINGS = {
    'TITLE': 'SafeBoda API',
    'DESCRIPTION': 'API for SafeBoda ride-sharing platform',
    'VERSION': '1.0.0',
}
```

**START ROTATIONS - Decide who will be Driver #1**

---

## PHASE 2: Building Authentication (60 minutes)

### Rotation 1: Serializers & Initial Setup (10 minutes)

**Objective**: Create all serializers needed for authentication

**Create `users/serializers.py`:**

```python
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'password2', 'first_name', 
                  'last_name', 'phone_number', 'user_type')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(**validated_data)
        return user


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user profile"""
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 
                  'phone_number', 'user_type', 'date_joined')
        read_only_fields = ('id', 'date_joined')
```

**Navigator Checklist:**
- [ ] Both serializers created
- [ ] Password validation included
- [ ] Password confirmation logic works
- [ ] All necessary fields present

**🔄 ROTATE DRIVER**

---

### Rotation 2: Registration Endpoint (10 minutes)

**Objective**: Create user registration view with JWT token generation

**Create `users/views.py`:**

```python
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserRegistrationSerializer, UserSerializer
from drf_spectacular.utils import extend_schema

class RegisterView(generics.CreateAPIView):
    """API endpoint for user registration"""
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Register new user",
        description="Create a new user account and receive JWT tokens"
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            },
            'message': 'User registered successfully'
        }, status=status.HTTP_201_CREATED)
```

**Navigator Checklist:**
- [ ] View created with correct imports
- [ ] Permission set to AllowAny
- [ ] JWT tokens generated after registration
- [ ] Response includes user data and tokens

**🔄 ROTATE DRIVER**

---

### Rotation 3: Login Endpoint (10 minutes)

**Objective**: Implement login endpoint with custom token response

**Add to `users/views.py`:**

```python
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom token serializer to include user data"""
    def validate(self, attrs):
        data = super().validate(attrs)
        data['user'] = UserSerializer(self.user).data
        return data


class LoginView(TokenObtainPairView):
    """API endpoint for user login"""
    serializer_class = CustomTokenObtainPairSerializer

    @extend_schema(
        summary="User login",
        description="Authenticate user and receive JWT tokens"
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
```

**Test the setup so far:**

```bash
# Run migrations
python manage.py makemigrations
python manage.py migrate

# Run server
python manage.py runserver
```

**Navigator Checklist:**
- [ ] Custom serializer extends TokenObtainPairSerializer
- [ ] User data included in response
- [ ] Migrations run successfully
- [ ] Server starts without errors

**🔄 ROTATE DRIVER**

---

### Rotation 4: Protected Profile Endpoint (10 minutes)

**Objective**: Create endpoint that requires authentication

**Add to `users/views.py`:**

```python
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

class UserProfileView(APIView):
    """API endpoint to retrieve and update user profile"""
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Get user profile",
        description="Retrieve authenticated user's profile"
    )
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    @extend_schema(
        summary="Update user profile",
        description="Update authenticated user's profile"
    )
    def put(self, request):
        serializer = UserSerializer(
            request.user, 
            data=request.data, 
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
```

**Navigator Checklist:**
- [ ] IsAuthenticated permission class used
- [ ] GET method retrieves current user
- [ ] PUT method allows updates
- [ ] Partial updates supported

**🔄 ROTATE DRIVER**

---

### Rotation 5: URL Configuration & Documentation (10 minutes)

**Objective**: Wire up all endpoints and enable documentation

**Create `users/urls.py`:**

```python
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import RegisterView, LoginView, UserProfileView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/', UserProfileView.as_view(), name='profile'),
]
```

**Update `safeboda/urls.py`:**

```python
from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/users/', include('users.urls')),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
```

**Verify everything works:**

```bash
# Restart server if needed
python manage.py runserver
```

**Visit:** `http://127.0.0.1:8000/api/docs/` - Should see Swagger UI

**Navigator Checklist:**
- [ ] All views mapped to URLs
- [ ] Documentation URLs working
- [ ] No errors in console
- [ ] All endpoints visible in Swagger

**🔄 ROTATE DRIVER**

---

### Rotation 6: Postman Collection & Testing (10 minutes)

**Objective**: Create comprehensive test suite

#### Setup Postman Environment
**Name**: "SafeBoda Dev"

**Variables**:
```
base_url: http://127.0.0.1:8000
access_token: (leave empty)
refresh_token: (leave empty)
```

#### Create 4 Essential Requests:

**1. Register User (POST)**
```
URL: {{base_url}}/api/users/register/
Method: POST
Body (JSON):
{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "password2": "SecurePass123!",
    "first_name": "Test",
    "last_name": "User",
    "phone_number": "+250788123456",
    "user_type": "passenger"
}

Tests:
pm.test("Status 201", () => pm.response.to.have.status(201));
pm.test("Has tokens", () => {
    const json = pm.response.json();
    pm.expect(json.tokens).to.have.property('access');
    pm.environment.set("access_token", json.tokens.access);
    pm.environment.set("refresh_token", json.tokens.refresh);
});
```

**2. Login (POST)**
```
URL: {{base_url}}/api/users/login/
Method: POST
Body (JSON):
{
    "email": "test@example.com",
    "password": "SecurePass123!"
}

Tests:
pm.test("Status 200", () => pm.response.to.have.status(200));
pm.test("Login success", () => {
    const json = pm.response.json();
    pm.environment.set("access_token", json.access);
});
```

**3. Get Profile (GET) - Protected**
```
URL: {{base_url}}/api/users/profile/
Method: GET
Headers:
    Authorization: Bearer {{access_token}}

Tests:
pm.test("Status 200", () => pm.response.to.have.status(200));
pm.test("Has user data", () => {
    const json = pm.response.json();
    pm.expect(json).to.have.property('email');
});
```

**4. Test Unauthorized (GET)**
```
URL: {{base_url}}/api/users/profile/
Method: GET
Headers: (No Authorization header)

Tests:
pm.test("Status 401", () => pm.response.to.have.status(401));
```

**Navigator Checklist:**
- [ ] Environment created
- [ ] All 4 requests created
- [ ] Tests written
- [ ] Run collection - all pass

**🔄 ROTATION COMPLETE**

---

## PHASE 3: Testing & Documentation (15 minutes)

**All team members collaborate**

### Final Testing (10 minutes)

1. **Run Postman Collection**
   - Execute all requests in sequence
   - Verify all tests pass
   - Test with different user types (passenger and rider)

2. **Manual Testing**
   - Try invalid passwords
   - Test with missing fields
   - Verify token expiration behavior
   - Test profile updates

3. **Export Collection**
   - Save as `SafeBoda_API.postman_collection.json`
   - Place in `/postman/` folder
   - Commit to repository

### Update README (5 minutes)

Add to repository's README.md:

```markdown
## Team Members
- [Name 1] - [GitHub username]
- [Name 2] - [GitHub username]
- [Name 3] - [GitHub username]

## What We Built
JWT authentication system
User registration endpoint
User login endpoint
Protected user profile endpoint
API documentation
Postman test suite

## API Endpoints

### Public Endpoints
- `POST /api/users/register/` - User registration
- `POST /api/users/login/` - User login
- `POST /api/users/token/refresh/` - Refresh access token

### Protected Endpoints (Requires Authentication)
- `GET /api/users/profile/` - Get user profile
- `PUT /api/users/profile/` - Update user profile

### Documentation
- Swagger UI: http://127.0.0.1:8000/api/docs/

## Testing
Import Postman collection from `/postman/SafeBoda_API.postman_collection.json`

## Key Learnings
[Fill in top 3 learnings from your team]
```

---



## Common Issues & Quick Fixes

### "Module not found" errors
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### 401 Unauthorized on protected endpoints
```
Ensure Postman header: Authorization: Bearer {{access_token}}
Check token is saved in environment variables
```

### Server won't start
```bash
# Check for syntax errors
python manage.py check

# Run migrations
python manage.py migrate
```

### Documentation not loading
```python
# Verify settings.py has:
'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema'
```


**Good luck! 🚀**
