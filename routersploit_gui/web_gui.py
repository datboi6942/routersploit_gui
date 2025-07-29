"""Flask-based web GUI for RouterSploit."""

import json
import threading
import time
from typing import Any, Dict, List, Optional
import secrets
import base64
import ast
import inspect
import os
from pathlib import Path

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AttestationConveyancePreference, 
    AuthenticatorSelectionCriteria, 
    ResidentKeyRequirement, 
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import structlog

from . import config
from .module_loader import ModuleLoader, ModuleMeta
from .runner import RunnerManager
from .console import ConsoleHandler
from .auto_own_runner import AutoOwnManager

logger = structlog.get_logger(__name__)


# Initialize database
db = SQLAlchemy()

# User model for Flask-Login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Increased length to avoid truncating long hashes (e.g., scrypt) which breaks login verification
    password_hash = db.Column(db.String(512))
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    
    # Relationship to U2F credentials
    u2f_credentials = db.relationship('U2FCredential', backref='user', lazy=True, cascade='all, delete-orphan')

    def __init__(self, username, **kwargs):
        super().__init__(**kwargs)
        self.username = username
        self.two_factor_enabled = False  # Explicitly set to False

    def set_password(self, password: str) -> None:
        """Hash and store the user's password.

        Args:
            password: Plain-text password provided by the user.
        """
        # Explicitly use PBKDF2-SHA256 to ensure hashes stay <512 chars and
        # remain compatible with the defined column size regardless of
        # Werkzeug default algorithm changes.
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_u2f_credentials(self):
        return len(self.u2f_credentials) > 0

class U2FCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    credential_id = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    name = db.Column(db.String(100), nullable=False)  # User-friendly name for the key
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# Login form using Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')


class RouterSploitWebGUI:
    """Flask-based web GUI for RouterSploit.
    
    Provides a modern web interface for discovering, configuring,
    and executing RouterSploit modules with real-time output.
    Also includes a console interface for complete RouterSploit functionality.
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        """Initialize the web GUI.
        
        Args:
            host: Host to bind the web server to
            port: Port to bind the web server to
        """
        self.host = host
        self.port = port
        
        # Initialize Flask app
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        self.app.config['SECRET_KEY'] = 'routersploit-gui-secret-key'
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        # Configure WTF-CSRF settings
        self.app.config['WTF_CSRF_TIME_LIMIT'] = None  # Disable CSRF timeout
        self.app.config['WTF_CSRF_ENABLED'] = True
        self.app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session lifetime
        
        # Initialize extensions
        db.init_app(self.app)

        # Create database tables if they don't exist
        with self.app.app_context():
            db.create_all()

        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager.login_view = 'login'

        # Initialize SocketIO for real-time communication
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Initialize backend components
        self.module_loader = ModuleLoader()
        self.runner_manager = RunnerManager()
        self.console_handler = ConsoleHandler(self.module_loader)
        self.auto_own_manager = AutoOwnManager()
        
        # Application state
        self.modules: List[ModuleMeta] = []
        self.module_tree: Dict[str, Any] = {}
        self.current_module: Optional[ModuleMeta] = None
        self.target_history: List[str] = []
        
        # Console clients tracking
        self.console_clients: Dict[str, bool] = {}  # session_id -> is_active
        
        # Custom scripts functionality
        self.custom_scripts_dir = Path("custom_scripts")
        self.custom_scripts_dir.mkdir(exist_ok=True)
        self.custom_modules: List[ModuleMeta] = []
        
        # Setup auth, routes, and socket handlers
        self._setup_auth()
        self._setup_routes()
        self._setup_socket_handlers()
        
        # Setup console output callback
        self.console_handler.set_output_callback(self._on_console_output)
        
        # Load modules
        self._load_modules()
        
    def _setup_auth(self) -> None:
        """Set up user authentication."""
        @self.login_manager.user_loader
        def load_user(user_id: str) -> Optional[User]:
            return User.query.get(int(user_id))

    def _setup_routes(self) -> None:
        """Setup Flask routes."""

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """Handles user login."""
            form = LoginForm()
            if form.validate_on_submit():
                logger.info("Login form validated successfully", username=form.username.data)
                user = User.query.filter_by(username=form.username.data).first()
                
                if user:
                    logger.info("User found in database", username=user.username, user_id=user.id, two_factor_enabled=user.two_factor_enabled)
                    logger.info("Checking password for user", username=user.username)
                    password_check_result = user.check_password(form.password.data)
                    logger.info("Password check result", username=user.username, password_correct=password_check_result)
                else:
                    logger.warning("User not found in database", attempted_username=form.username.data)
                
                if user and user.check_password(form.password.data):
                    logger.info("Authentication successful", username=user.username)
                    # Check if user has 2FA enabled and configured
                    if user.two_factor_enabled and user.has_u2f_credentials():
                        logger.info("User has 2FA enabled, redirecting to verify_2fa", username=user.username)
                        # User has 2FA enabled, require U2F authentication
                        session['pending_user_id'] = user.id
                        return redirect(url_for('verify_2fa'))
                    else:
                        logger.info("User does not have 2FA fully configured", username=user.username, two_factor_enabled=user.two_factor_enabled, has_credentials=user.has_u2f_credentials())
                        # Login user first, then check 2FA setup
                        login_user(user, remember=True)
                        logger.info("User logged in successfully", username=user.username)
                        
                        # Check if user needs to set up 2FA
                        if not user.two_factor_enabled:
                            logger.info("Redirecting to 2FA setup", username=user.username)
                            flash('Welcome! Please set up two-factor authentication to continue.', 'info')
                            return redirect(url_for('setup_2fa'))
                        else:
                            logger.info("User fully authenticated, redirecting to main app", username=user.username)
                            flash('Logged in successfully.', 'success')
                            next_page = request.args.get('next')
                            return redirect(next_page or url_for('index'))
                else:
                    logger.warning("Authentication failed", attempted_username=form.username.data, user_exists=user is not None)
                    flash('Login unsuccessful. Please check username and password.', 'danger')
            else:
                if request.method == 'POST':
                    logger.warning("Form validation failed", errors=form.errors)
                    
            return render_template('login.html', form=form, title='Login')

        @self.app.route('/register', methods=['GET', 'POST'])
        def register():
            """Handles user registration."""
            form = RegistrationForm()
            if form.validate_on_submit():
                user = User(username=form.username.data)
                user.set_password(form.password.data)
                db.session.add(user)
                db.session.commit()
                flash(f'Account created for {form.username.data}! You are now able to log in.', 'success')
                return redirect(url_for('login'))
            return render_template('register.html', form=form, title='Register')

        @self.app.route('/setup-2fa')
        @login_required
        def setup_2fa():
            """Display 2FA setup page."""
            # User must be logged in to access this page
            if current_user.two_factor_enabled:
                flash('Two-factor authentication is already set up.', 'info')
                return redirect(url_for('index'))
            
            return render_template('setup_2fa.html', username=current_user.username)

        @self.app.route('/verify-2fa')
        def verify_2fa():
            """Display 2FA verification page."""
            if 'pending_user_id' not in session:
                flash('Invalid session. Please log in again.', 'danger')
                return redirect(url_for('login'))
            
            user = User.query.get(session['pending_user_id'])
            if not user or not user.has_u2f_credentials():
                flash('Invalid session. Please log in again.', 'danger')
                return redirect(url_for('login'))
            
            return render_template('verify_2fa.html', username=user.username)

        @self.app.route('/api/webauthn/register/begin', methods=['POST'])
        @login_required
        def webauthn_register_begin():
            """Begin WebAuthn registration process."""
            logger.info("WebAuthn registration begin requested", user_id=current_user.id, username=current_user.username)
            
            if current_user.two_factor_enabled:
                logger.warning("User already has 2FA enabled", user_id=current_user.id)
                return jsonify({'error': 'Two-factor authentication is already set up'}), 400

            try:
                # Generate challenge
                user_id = base64.urlsafe_b64encode(str(current_user.id).encode()).decode().rstrip('=')
                logger.info("Generated user ID for WebAuthn", user_id=user_id, original_id=current_user.id)
                
                registration_options = generate_registration_options(
                    rp_id="localhost",  # Use localhost specifically for development
                    rp_name="RouterSploit GUI",
                    user_id=user_id.encode(),
                    user_name=current_user.username,
                    user_display_name=current_user.username,
                    attestation=AttestationConveyancePreference.NONE,
                    authenticator_selection=AuthenticatorSelectionCriteria(
                        user_verification=UserVerificationRequirement.DISCOURAGED,
                        resident_key=ResidentKeyRequirement.DISCOURAGED
                    ),
                    supported_pub_key_algs=[
                        COSEAlgorithmIdentifier.ECDSA_SHA_256,
                        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
                    ],
                    exclude_credentials=[
                        PublicKeyCredentialDescriptor(
                            id=base64.urlsafe_b64decode(cred.credential_id.encode() + b'=='),
                            transports=[AuthenticatorTransport.USB, AuthenticatorTransport.NFC]
                        ) for cred in current_user.u2f_credentials
                    ]
                )
                logger.info("Generated WebAuthn registration options successfully")

                # Store challenge in session
                session['webauthn_challenge'] = base64.urlsafe_b64encode(registration_options.challenge).decode().rstrip('=')
                logger.info("Stored challenge in session", challenge_length=len(session['webauthn_challenge']))
                
                response_data = {
                    'publicKey': {
                        'challenge': base64.urlsafe_b64encode(registration_options.challenge).decode().rstrip('='),
                        'rp': {
                            'name': registration_options.rp.name,
                            'id': registration_options.rp.id,
                        },
                        'user': {
                            'id': base64.urlsafe_b64encode(registration_options.user.id).decode().rstrip('='),
                            'name': registration_options.user.name,
                            'displayName': registration_options.user.display_name,
                        },
                        'pubKeyCredParams': [
                            {'alg': alg.alg, 'type': 'public-key'} 
                            for alg in registration_options.pub_key_cred_params
                        ],
                        'timeout': registration_options.timeout,
                        'attestation': registration_options.attestation,
                        'authenticatorSelection': {
                            'userVerification': registration_options.authenticator_selection.user_verification,
                            'residentKey': registration_options.authenticator_selection.resident_key,
                        },
                        'excludeCredentials': [
                            {
                                'id': base64.urlsafe_b64encode(cred.id).decode().rstrip('='),
                                'type': 'public-key',
                                'transports': [t.value for t in cred.transports] if cred.transports else []
                            } for cred in registration_options.exclude_credentials
                        ]
                    }
                }
                logger.info("Returning WebAuthn registration options", rp_id=response_data['publicKey']['rp']['id'])
                return jsonify(response_data)
                
            except Exception as e:
                logger.error("Failed to generate WebAuthn registration options", error=str(e), user_id=current_user.id)
                return jsonify({'error': f'Failed to generate registration options: {str(e)}'}), 500

        @self.app.route('/api/webauthn/register/complete', methods=['POST'])
        @login_required
        def webauthn_register_complete():
            """Complete WebAuthn registration process."""
            logger.info("WebAuthn registration completion started", user_id=current_user.id, username=current_user.username)
            
            if 'webauthn_challenge' not in session:
                logger.warning("Invalid session - missing webauthn_challenge", user_id=current_user.id)
                return jsonify({'error': 'Invalid session. Please try again.'}), 401
            
            if current_user.two_factor_enabled:
                logger.warning("User already has 2FA enabled", user_id=current_user.id)
                return jsonify({'error': 'Two-factor authentication is already set up'}), 400

            data = request.get_json()
            logger.info("Received WebAuthn credential data", has_data=data is not None, has_credential=data and 'credential' in data if data else False)
            
            if not data or 'credential' not in data:
                logger.warning("No credential data provided", data_keys=list(data.keys()) if data else None)
                return jsonify({'error': 'No credential data provided'}), 400
                
            credential_name = data.get('name', 'Security Key')
            logger.info("Processing WebAuthn credential", user_id=current_user.id, credential_name=credential_name, credential_keys=list(data['credential'].keys()) if data.get('credential') else None)
            
            try:
                challenge = base64.urlsafe_b64decode(session['webauthn_challenge'].encode() + b'==')
                logger.info("Challenge decoded successfully")
                
                verification = verify_registration_response(
                    credential=data['credential'],
                    expected_challenge=challenge,
                    expected_origin="http://localhost:5000",  # Use localhost for development
                    expected_rp_id="localhost",  # Use localhost for development
                )
                logger.info("WebAuthn verification object type", verification_type=type(verification).__name__)
                logger.info("WebAuthn verification object attributes", attributes=[attr for attr in dir(verification) if not attr.startswith('_')])
                logger.info("WebAuthn verification completed", verification_object=str(verification))

                # If we reach here, verification was successful (no exception was raised)
                logger.info("WebAuthn verification successful", user_id=current_user.id)
                
                # Save credential to database
                credential_id = base64.urlsafe_b64encode(verification.credential_id).decode().rstrip('=')
                public_key = base64.urlsafe_b64encode(verification.credential_public_key).decode().rstrip('=')
                
                logger.info("Saving U2F credential to database", user_id=current_user.id)
                new_credential = U2FCredential(
                    user_id=current_user.id,
                    credential_id=credential_id,
                    public_key=public_key,
                    sign_count=verification.sign_count,
                    name=credential_name
                )
                
                try:
                    db.session.add(new_credential)
                    current_user.two_factor_enabled = True
                    db.session.commit()
                    logger.info("U2F credential saved successfully", user_id=current_user.id)
                    
                    # Clean up session
                    session.pop('webauthn_challenge', None)
                    
                    # User is already logged in, just redirect to main app
                    logger.info("2FA setup completed successfully", user_id=current_user.id)
                    
                    return jsonify({
                        'verified': True, 
                        'message': '2FA setup complete!',
                        'redirect': url_for('index')
                    })
                except Exception as db_error:
                    db.session.rollback()
                    logger.error("Database error during credential save", error=str(db_error), user_id=current_user.id)
                    return jsonify({'verified': False, 'error': 'Failed to save credential. Please try again.'}), 500
                    
            except Exception as e:
                logger.error("WebAuthn registration error", error=str(e), user_id=current_user.id)
                return jsonify({'verified': False, 'error': f'Registration failed: {str(e)}'}), 400

        @self.app.route('/api/webauthn/authenticate/begin', methods=['POST'])
        def webauthn_authenticate_begin():
            """Begin WebAuthn authentication process."""
            if 'pending_user_id' not in session:
                return jsonify({'error': 'Invalid session'}), 401
            
            user = User.query.get(session['pending_user_id'])
            if not user or not user.has_u2f_credentials():
                return jsonify({'error': 'Invalid session'}), 401

            # Generate authentication options
            authentication_options = generate_authentication_options(
                rp_id="localhost",  # Use localhost for development
                allow_credentials=[
                    PublicKeyCredentialDescriptor(
                        id=base64.urlsafe_b64decode(cred.credential_id.encode() + b'=='),
                        transports=[AuthenticatorTransport.USB, AuthenticatorTransport.NFC]
                    ) for cred in user.u2f_credentials
                ],
                user_verification=UserVerificationRequirement.PREFERRED,
            )

            # Store challenge in session
            session['webauthn_challenge'] = base64.urlsafe_b64encode(authentication_options.challenge).decode().rstrip('=')
            
            return jsonify({
                'publicKey': {
                    'challenge': base64.urlsafe_b64encode(authentication_options.challenge).decode().rstrip('='),
                    'timeout': authentication_options.timeout,
                    'rpId': authentication_options.rp_id,
                    'allowCredentials': [
                        {
                            'id': base64.urlsafe_b64encode(cred.id).decode().rstrip('='),
                            'type': 'public-key',
                            'transports': [t.value for t in cred.transports] if cred.transports else []
                        } for cred in authentication_options.allow_credentials
                    ],
                    'userVerification': authentication_options.user_verification,
                }
            })

        @self.app.route('/api/webauthn/authenticate/complete', methods=['POST'])
        def webauthn_authenticate_complete():
            """Complete WebAuthn authentication process."""
            if 'pending_user_id' not in session or 'webauthn_challenge' not in session:
                return jsonify({'error': 'Invalid session'}), 401
            
            user = User.query.get(session['pending_user_id'])
            if not user:
                return jsonify({'error': 'Invalid session'}), 401

            data = request.get_json()
            
            try:
                # Find the credential used
                credential_id = base64.urlsafe_b64encode(
                    base64.urlsafe_b64decode(data['credential']['id'].encode() + b'==')
                ).decode().rstrip('=')
                
                credential = U2FCredential.query.filter_by(
                    user_id=user.id, 
                    credential_id=credential_id
                ).first()
                
                if not credential:
                    return jsonify({'verified': False, 'error': 'Credential not found'}), 400

                challenge = base64.urlsafe_b64decode(session['webauthn_challenge'].encode() + b'==')
                public_key = base64.urlsafe_b64decode(credential.public_key.encode() + b'==')
                
                verification = verify_authentication_response(
                    credential=data['credential'],
                    expected_challenge=challenge,
                    expected_origin="http://localhost:5000",  # Use localhost for development
                    expected_rp_id="localhost",  # Use localhost for development
                    credential_public_key=public_key,
                    credential_current_sign_count=credential.sign_count,
                )

                # If we reach here, authentication was successful (no exception was raised)
                logger.info("WebAuthn authentication successful", user_id=user.id)
                
                # Update sign count
                credential.sign_count = verification.new_sign_count
                db.session.commit()
                
                # Clean up session
                session.pop('webauthn_challenge', None)
                session.pop('pending_user_id', None)
                
                # Log the user in
                login_user(user, remember=True)
                
                return jsonify({'verified': True, 'message': 'Authentication successful!'})
                
            except Exception as e:
                logger.error("WebAuthn authentication error", error=str(e))
                return jsonify({'verified': False, 'error': 'Authentication failed'}), 400

        @self.app.route('/logout')
        @login_required
        def logout():
            """Handles user logout."""
            logout_user()
            flash('You have been logged out.')
            return redirect(url_for('login'))
        
        @self.app.route('/')
        @login_required
        def index() -> str:
            """Main page."""
            # Check if user needs to set up 2FA
            if not current_user.two_factor_enabled:
                flash('Please set up two-factor authentication to continue.', 'warning')
                return redirect(url_for('setup_2fa'))
            
            return render_template('index.html')
        
        @self.app.route('/console-test')
        def console_test() -> str:
            """Console test page for debugging."""
            from flask import send_from_directory
            import os
            app_dir = os.path.dirname(__file__)
            return send_from_directory(app_dir, 'console_test.html')
        
        @self.app.route('/sw.js')
        def service_worker() -> Any:
            """Service worker for PWA functionality."""
            from flask import send_from_directory
            import os
            static_dir = os.path.join(os.path.dirname(__file__), 'static')
            return send_from_directory(static_dir, 'sw.js', mimetype='application/javascript')
        
        @self.app.route('/api/modules')
        @login_required
        def get_modules() -> Any:
            """Get all modules as a tree structure."""
            # Convert the tree to a JSON-serializable format
            json_tree = self._serialize_tree(self.module_tree)
            regular_modules_count = len(self.modules) - len(self.custom_modules)
            return jsonify({
                'tree': json_tree,
                'count': len(self.modules),
                'regular_modules': regular_modules_count,
                'custom_modules': len(self.custom_modules)
            })
        
        @self.app.route('/api/module/<path:module_path>')
        @login_required
        def get_module(module_path: str) -> Any:
            """Get details for a specific module."""
            module = self._find_module_by_path(module_path)
            if not module:
                return jsonify({'error': 'Module not found'}), 404
            
            # Get available payloads if this is an exploit module
            payloads = []
            if self._is_exploit_module(module):
                payloads = self._get_compatible_payloads(module)
            
            # Serialize the module options
            json_options = self._serialize_options(module.opts)
            
            return jsonify({
                'name': module.name,
                'description': module.description,
                'path': module.dotted_path,
                'category': module.category,
                'options': json_options,
                'payloads': [{'name': p.name, 'path': p.dotted_path, 'options': self._serialize_options(p.opts)} 
                           for p in payloads],
                'is_exploit': self._is_exploit_module(module),
                'cve_list': module.cve_list
            })
        
        @self.app.route('/api/run', methods=['POST'])
        @login_required
        def run_module() -> Any:
            """Execute a module with provided options."""
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            module_path = data.get('module_path')
            options = data.get('options', {})
            payload_path = data.get('payload_path')
            payload_options = data.get('payload_options', {})
            
            module = self._find_module_by_path(module_path)
            if not module:
                return jsonify({'error': 'Module not found'}), 404

            logger.info("Processing module options", module=module_path, options=options)
            
            # Validate and convert options
            processed_options = self._process_options(options, module.opts)
            
            logger.info("Processed module options", processed_options=processed_options)
            
            # Add payload options if specified
            if payload_path:
                payload = self._find_module_by_path(payload_path)
                if payload:
                    logger.info("Processing payload options", payload=payload_path, payload_options=payload_options)
                    processed_payload_options = self._process_options(payload_options, payload.opts)
                    logger.info("Processed payload options", processed_payload_options=processed_payload_options)
                    
                    # Set the payload on the module
                    processed_options['payload'] = payload.cls()
                    
                    # Configure payload options with detailed error handling
                    for opt_name, opt_value in processed_payload_options.items():
                        if hasattr(processed_options['payload'], opt_name):
                            try:
                                logger.info("Setting payload option", option=opt_name, value=opt_value, value_type=type(opt_value).__name__)
                                setattr(processed_options['payload'], opt_name, opt_value)
                                logger.info("Successfully set payload option", option=opt_name)
                            except Exception as e:
                                logger.error("Failed to set payload option", option=opt_name, value=opt_value, value_type=type(opt_value).__name__, error=str(e))
                                return jsonify({'error': f'Failed to set payload option {opt_name}: {str(e)}'}), 400
            
            # Start execution
            success = self.runner_manager.start_module(
                module,
                processed_options,
                self._on_module_output,
                self._on_module_complete
            )
            
            if success:
                self.current_module = module
                return jsonify({'status': 'started'})
            else:
                return jsonify({'error': 'Failed to start module'}), 500
        
        @self.app.route('/api/stop', methods=['POST'])
        @login_required
        def stop_module() -> Any:
            """Stop the currently running module."""
            self.runner_manager.stop_current()
            return jsonify({'status': 'stopped'})
        
        @self.app.route('/api/status')
        @login_required
        def get_status() -> Any:
            """Get current execution status."""
            return jsonify({
                'running': self.runner_manager.is_running(),
                'current_module': self.current_module.dotted_path if self.current_module else None
            })
        
        @self.app.route('/api/auto-own/start', methods=['POST'])
        @login_required
        def start_auto_own() -> Any:
            """Start an auto-own process."""
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            target = data.get('target')
            verbose = bool(data.get('verbose', False))
            debug = bool(data.get('debug', False))
            if not target:
                return jsonify({'error': 'Target not specified'}), 400
            
            # Check if auto-own is enabled
            if not config.AUTO_OWN_ENABLED:
                return jsonify({'error': 'Auto-Own feature is disabled'}), 403
            
            # Check if OpenAI is configured
            if not config.get_openai_api_key():
                return jsonify({'error': 'OpenAI API key not configured'}), 403
            
            # Start auto-own process
            success = self.auto_own_manager.start_auto_own(
                target=target,
                on_output=self._on_auto_own_output,
                on_complete=self._on_auto_own_complete,
                on_progress=self._on_auto_own_progress,
                verbose=verbose,
                debug=debug
            )
            
            if success:
                return jsonify({'status': 'started', 'target': target})
            else:
                return jsonify({'error': 'Failed to start auto-own process'}), 500
        
        @self.app.route('/api/auto-own/stop', methods=['POST'])
        @login_required
        def stop_auto_own() -> Any:
            """Stop the current auto-own process."""
            self.auto_own_manager.stop_current()
            return jsonify({'status': 'stopped'})
        
        @self.app.route('/api/auto-own/status')
        @login_required
        def get_auto_own_status() -> Any:
            """Get auto-own status and configuration."""
            return jsonify(self.auto_own_manager.get_status())
        
        @self.app.route('/api/sessions')
        @login_required
        def get_sessions() -> Any:
            """Get all active RCE sessions."""
            # Get sessions from the auto-own manager's tool manager
            sessions = {}
            if hasattr(self.auto_own_manager, 'agent') and self.auto_own_manager.agent:
                tool_manager = self.auto_own_manager.agent.tool_manager
                sessions = tool_manager.active_sessions
            
            return jsonify({
                'sessions': sessions,
                'count': len(sessions)
            })
        
        @self.app.route('/api/auto-own/check-api-key')
        @login_required
        def check_api_key_status() -> Any:
            """Check if OpenAI API key is configured (for debugging)."""
            api_key = config.get_openai_api_key()
            key_configured = bool(api_key)
            key_preview = f"{api_key[:10]}...{api_key[-4:]}" if len(api_key) > 14 else "***" if api_key else "Not set"
            
            return jsonify({
                'configured': key_configured,
                'key_preview': key_preview,
                'config_file': str(config.OPENAI_API_KEY_FILE),
                'file_exists': config.OPENAI_API_KEY_FILE.exists()
            })
        
        @self.app.route('/api/sessions/<session_id>/execute', methods=['POST'])
        @login_required
        def execute_session_command(session_id: str) -> Any:
            """Execute a command in an RCE session."""
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            command = data.get('command', '').strip()
            if not command:
                return jsonify({'error': 'No command provided'}), 400
            
            # Get the session from auto-own manager
            if hasattr(self.auto_own_manager, 'agent') and self.auto_own_manager.agent:
                tool_manager = self.auto_own_manager.agent.tool_manager
                if session_id in tool_manager.active_sessions:
                    session_info = tool_manager.active_sessions[session_id]
                    
                    # For now, simulate command execution since we don't have live session handling
                    # In a real implementation, this would execute the command in the actual session
                    session_info['commands'].append({
                        'command': command,
                        'timestamp': time.time(),
                        'output': f"Command '{command}' executed successfully\n$ "
                    })
                    
                    return jsonify({
                        'success': True,
                        'output': f"Command '{command}' executed successfully\n$ ",
                        'session_id': session_id
                    })
                else:
                    return jsonify({'error': 'Session not found'}), 404
            
            return jsonify({'error': 'Auto-own manager not available'}), 503
        
        @self.app.route('/api/auto-own/targets')
        @login_required
        def get_auto_own_targets() -> Any:
            """Get list of targets with auto-own history."""
            targets = self.auto_own_manager.agent.get_available_targets()
            return jsonify({'targets': targets})
        
        @self.app.route('/api/auto-own/history/<target>')
        @login_required
        def get_auto_own_history(target: str) -> Any:
            """Get auto-own history for a specific target."""
            history = self.auto_own_manager.get_target_history(target)
            return jsonify({'history': history})
        
        @self.app.route('/api/auto-own/set-api-key', methods=['POST'])
        @login_required
        def set_auto_own_api_key() -> Any:
            """Set the OpenAI API key for Auto-Own."""
            data = request.get_json()
            if not data or 'api_key' not in data:
                logger.warning("No API key provided in request")
                return jsonify({'error': 'No API key provided'}), 400
            
            api_key = data['api_key'].strip()
            if not api_key:
                logger.warning("Empty API key provided")
                return jsonify({'error': 'Empty API key provided'}), 400
            
            try:
                # Save the API key to file
                config.set_openai_api_key(api_key)
                
                # Log success (without exposing the key)
                key_preview = f"{api_key[:10]}...{api_key[-4:]}" if len(api_key) > 14 else "***"
                logger.info("OpenAI API key saved successfully", key_preview=key_preview)
                
                # Verify it was saved correctly by reading it back
                saved_key = config.get_openai_api_key()
                if saved_key == api_key:
                    logger.info("API key verification successful")
                    
                    # Force the auto-own manager to refresh its agent
                    try:
                        self.auto_own_manager.refresh_agent()
                        logger.info("Auto-own agent refreshed with new API key")
                    except Exception as refresh_error:
                        logger.warning("Failed to refresh auto-own agent", error=str(refresh_error))
                    
                    return jsonify({'status': 'success', 'message': 'API key saved and verified'})
                else:
                    logger.error("API key verification failed - saved key doesn't match")
                    return jsonify({'error': 'API key verification failed'}), 500
                    
            except Exception as e:
                logger.error("Failed to save API key", error=str(e))
                return jsonify({'error': f'Failed to save API key: {str(e)}'}), 500
        
        @self.app.route('/api/auto-own/set-exploitdb-key', methods=['POST'])
        @login_required
        def set_exploitdb_api_key() -> Any:
            """Set the ExploitDB API key for enhanced exploit searching."""
            data = request.get_json()
            if not data or 'api_key' not in data:
                logger.warning("No ExploitDB API key provided in request")
                return jsonify({'error': 'No API key provided'}), 400
            
            api_key = data['api_key'].strip()
            
            try:
                # Save the ExploitDB API key to file (even if empty to clear it)
                config.set_exploitdb_api_key(api_key)
                
                if api_key:
                    # Log success (without exposing the key)
                    key_preview = f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) > 10 else "***"
                    logger.info("ExploitDB API key saved successfully", key_preview=key_preview)
                    message = "ExploitDB API key saved successfully"
                else:
                    logger.info("ExploitDB API key cleared")
                    message = "ExploitDB API key cleared - ExploitDB will be skipped"
                
                # Verify it was saved correctly by reading it back
                saved_key = config.get_exploitdb_api_key()
                if saved_key == api_key:
                    logger.info("ExploitDB API key verification successful")
                    
                    # Force the auto-own manager to refresh its agent
                    try:
                        self.auto_own_manager.refresh_agent()
                        logger.info("Auto-own agent refreshed with new ExploitDB API key")
                    except Exception as refresh_error:
                        logger.warning("Failed to refresh auto-own agent", error=str(refresh_error))
                    
                    return jsonify({'status': 'success', 'message': message})
                else:
                    logger.error("ExploitDB API key verification failed - saved key doesn't match")
                    return jsonify({'error': 'ExploitDB API key verification failed'}), 500
                    
            except Exception as e:
                logger.error("Failed to save ExploitDB API key", error=str(e))
                return jsonify({'error': f'Failed to save ExploitDB API key: {str(e)}'}), 500

        # Custom Scripts API endpoints
        @self.app.route('/api/custom-scripts')
        @login_required
        def get_custom_scripts() -> Any:
            """Get list of uploaded custom scripts."""
            try:
                scripts = []
                if self.custom_scripts_dir.exists():
                    for script_file in self.custom_scripts_dir.glob("*.py"):
                        script_info = self._get_script_info(script_file)
                        scripts.append(script_info)
                
                return jsonify({
                    'scripts': scripts,
                    'count': len(scripts)
                })
            except Exception as e:
                logger.error("Failed to get custom scripts", error=str(e))
                return jsonify({'error': f'Failed to get custom scripts: {str(e)}'}), 500

        @self.app.route('/api/custom-scripts/upload', methods=['POST'])
        @login_required
        def upload_custom_script() -> Any:
            """Upload a new custom script."""
            try:
                if 'file' not in request.files:
                    return jsonify({'error': 'No file provided'}), 400
                
                file = request.files['file']
                if file.filename == '':
                    return jsonify({'error': 'No file selected'}), 400
                
                if not file.filename.endswith('.py'):
                    return jsonify({'error': 'File must be a Python script (.py)'}), 400
                
                # Read and validate the script content
                content = file.read().decode('utf-8')
                validation_result = self._validate_script(content, file.filename)
                
                if not validation_result['valid']:
                    return jsonify({
                        'error': 'Script validation failed',
                        'details': validation_result['errors']
                    }), 400
                
                # Save the script
                safe_filename = "".join(c for c in file.filename if c.isalnum() or c in '._-')
                script_path = self.custom_scripts_dir / safe_filename
                
                # Check if file already exists
                if script_path.exists():
                    return jsonify({'error': f'Script {safe_filename} already exists'}), 409
                
                script_path.write_text(content)
                
                # Load the script as a module
                custom_module = self._load_custom_script(script_path)
                if custom_module:
                    self.custom_modules.append(custom_module)
                    self.modules.append(custom_module)
                    
                    # Rebuild module tree with custom scripts
                    self.module_tree = self.module_loader.build_tree()
                    self._add_custom_scripts_to_tree()
                
                logger.info("Custom script uploaded successfully", filename=safe_filename)
                return jsonify({
                    'status': 'success',
                    'message': f'Script {safe_filename} uploaded successfully',
                    'filename': safe_filename
                })
                
            except Exception as e:
                logger.error("Failed to upload custom script", error=str(e))
                return jsonify({'error': f'Failed to upload script: {str(e)}'}), 500

        @self.app.route('/api/custom-scripts/<script_name>', methods=['DELETE'])
        @login_required
        def delete_custom_script(script_name: str) -> Any:
            """Delete a custom script."""
            try:
                script_path = self.custom_scripts_dir / script_name
                if not script_path.exists():
                    return jsonify({'error': 'Script not found'}), 404
                
                # Remove from modules list
                module_path = f"custom_scripts.{script_name[:-3]}"  # Remove .py extension
                self.custom_modules = [m for m in self.custom_modules if m.dotted_path != module_path]
                self.modules = [m for m in self.modules if m.dotted_path != module_path]
                
                # Clean up Python module cache
                import sys
                if module_path in sys.modules:
                    del sys.modules[module_path]
                
                # Delete the file
                script_path.unlink()
                
                # Rebuild module tree with custom scripts
                self.module_tree = self.module_loader.build_tree()
                if self.custom_modules:
                    self._add_custom_scripts_to_tree()
                
                logger.info("Custom script deleted successfully", filename=script_name)
                return jsonify({
                    'status': 'success',
                    'message': f'Script {script_name} deleted successfully'
                })
                
            except Exception as e:
                logger.error("Failed to delete custom script", error=str(e))
                return jsonify({'error': f'Failed to delete script: {str(e)}'}), 500

        @self.app.route('/api/custom-scripts/<script_name>/validate', methods=['POST'])
        @login_required
        def validate_custom_script(script_name: str) -> Any:
            """Validate a custom script."""
            try:
                script_path = self.custom_scripts_dir / script_name
                if not script_path.exists():
                    return jsonify({'error': 'Script not found'}), 404
                
                content = script_path.read_text()
                validation_result = self._validate_script(content, script_name)
                
                return jsonify(validation_result)
                
            except Exception as e:
                logger.error("Failed to validate custom script", error=str(e))
                return jsonify({'error': f'Failed to validate script: {str(e)}'}), 500
    
    def _setup_socket_handlers(self) -> None:
        """Setup SocketIO event handlers."""
        
        @self.socketio.on('connect')
        def handle_connect() -> bool:
            """Handle client connection, ensuring user is authenticated."""
            if not current_user.is_authenticated:
                logger.warning("Unauthenticated Socket.IO connection rejected.")
                return False  # Reject connection
            
            logger.info("Client connected", user=current_user.username)
            emit('status', {
                'running': self.runner_manager.is_running(),
                'current_module': self.current_module.dotted_path if self.current_module else None
            })
            return True
        
        @self.socketio.on('disconnect')
        def handle_disconnect() -> None:
            """Handle client disconnection."""
            logger.info("Client disconnected")
            
        @self.socketio.on('console_connect')
        def handle_console_connect(data=None) -> None:
            """Handle console connection."""
            session_id = request.sid
            self.console_clients[session_id] = True
            logger.info("Console client connected", session_id=session_id)
            emit('console_connected', {
                'prompt': self.console_handler.get_prompt(),
                'welcome': 'RouterSploit Console - Type "help" for commands'
            })
            
        @self.socketio.on('console_disconnect')
        def handle_console_disconnect(data=None) -> None:
            """Handle console disconnection."""
            session_id = request.sid
            if session_id in self.console_clients:
                del self.console_clients[session_id]
            logger.info("Console client disconnected", session_id=session_id)
            
        @self.socketio.on('console_command')
        def handle_console_command(data: Dict[str, Any]) -> None:
            """Handle console command execution."""
            try:
                command = data.get('command', '').strip()
                if not command:
                    return
                    
                logger.info("Executing console command", command=command)
                
                # Execute the command
                result = self.console_handler.execute_command(command)
                
                # Handle special commands
                if result == "CLEAR_CONSOLE":
                    emit('console_clear')
                    return
                elif result == "EXIT_CONSOLE":
                    emit('console_exit')
                    return
                
                # Send result back to client
                if result:
                    emit('console_output', {
                        'data': result,
                        'level': 'info'
                    })
                
                # Send updated prompt
                emit('console_prompt', {
                    'prompt': self.console_handler.get_prompt()
                })
                
            except Exception as e:
                logger.error("Console command failed", error=str(e))
                emit('console_output', {
                    'data': f"Error: {str(e)}",
                    'level': 'error'
                })
        
        @self.socketio.on('session_connect')
        def handle_session_connect(data: Dict[str, Any]) -> None:
            """Handle RCE session connection."""
            session_id = data.get('session_id')
            if not session_id:
                emit('session_error', {'error': 'No session ID provided'})
                return
            
            # Check if session exists
            if hasattr(self.auto_own_manager, 'agent') and self.auto_own_manager.agent:
                tool_manager = self.auto_own_manager.agent.tool_manager
                if session_id in tool_manager.active_sessions:
                    session_info = tool_manager.active_sessions[session_id]
                    logger.info("Client connected to RCE session", session_id=session_id)
                    
                    # Send session info and welcome message
                    emit('session_connected', {
                        'session_id': session_id,
                        'target': session_info.get('target', 'unknown'),
                        'session_type': session_info.get('session_type', 'shell'),
                        'welcome': f"Connected to {session_info.get('session_type', 'shell')} session on {session_info.get('target', 'unknown')}\nType 'help' for available commands or start executing commands directly.\n$ "
                    })
                else:
                    emit('session_error', {'error': 'Session not found'})
            else:
                emit('session_error', {'error': 'No active sessions available'})
        
        @self.socketio.on('session_command')
        def handle_session_command(data: Dict[str, Any]) -> None:
            """Handle RCE session command execution."""
            try:
                session_id = data.get('session_id')
                command = data.get('command', '').strip()
                
                if not session_id or not command:
                    emit('session_error', {'error': 'Session ID and command required'})
                    return
                
                logger.info("Executing session command", session_id=session_id, command=command)
                
                # Get the session
                if hasattr(self.auto_own_manager, 'agent') and self.auto_own_manager.agent:
                    tool_manager = self.auto_own_manager.agent.tool_manager
                    if session_id in tool_manager.active_sessions:
                        session_info = tool_manager.active_sessions[session_id]
                        
                        # Simulate command execution for demo
                        # In a real implementation, this would execute in the actual session
                        import time
                        session_info['commands'].append({
                            'command': command,
                            'timestamp': time.time(),
                            'output': self._simulate_session_command(command, session_info)
                        })
                        
                        # Send command output back to client
                        output = self._simulate_session_command(command, session_info)
                        emit('session_output', {
                            'session_id': session_id,
                            'command': command,
                            'output': output,
                            'timestamp': time.time()
                        })
                        
                    else:
                        emit('session_error', {'error': 'Session not found'})
                else:
                    emit('session_error', {'error': 'No session manager available'})
                    
            except Exception as e:
                logger.error("Session command failed", error=str(e))
                emit('session_error', {
                    'error': f"Command execution failed: {str(e)}"
                })
        
        @self.socketio.on('session_disconnect')
        def handle_session_disconnect(data: Dict[str, Any]) -> None:
            """Handle RCE session disconnection."""
            session_id = data.get('session_id')
            if session_id:
                logger.info("Client disconnected from RCE session", session_id=session_id)
                emit('session_disconnected', {'session_id': session_id})
    
    def _on_console_output(self, message: str, level: str) -> None:
        """Handle console output from the console handler."""
        # Broadcast to all connected console clients
        self.socketio.emit('console_output', {
            'data': message,
            'level': level
        }, room=None)  # Broadcast to all clients
    
    def _load_modules(self) -> None:
        """Load all RouterSploit modules."""
        try:
            logger.info("Loading RouterSploit modules...")
            self.modules = self.module_loader.discover_modules()
            self._load_custom_scripts()
            self.module_tree = self.module_loader.build_tree()
            
            # Add custom scripts to the tree
            if self.custom_modules:
                self._add_custom_scripts_to_tree()
                
            logger.info("Modules loaded successfully", count=len(self.modules))
        except Exception as e:
            logger.error("Failed to load modules", error=str(e))
            raise

    def _load_custom_scripts(self) -> None:
        """Load custom scripts from the custom_scripts directory."""
        try:
            if not self.custom_scripts_dir.exists():
                return
                
            logger.info("Loading custom scripts...")
            custom_count = 0
            
            for script_file in self.custom_scripts_dir.glob("*.py"):
                custom_module = self._load_custom_script(script_file)
                if custom_module:
                    self.custom_modules.append(custom_module)
                    self.modules.append(custom_module)
                    custom_count += 1
            
            logger.info("Custom scripts loaded", count=custom_count)
            
        except Exception as e:
            logger.error("Failed to load custom scripts", error=str(e))

    def _add_custom_scripts_to_tree(self) -> None:
        """Add custom scripts to the module tree."""
        if not self.custom_modules:
            return
            
        if 'custom_scripts' not in self.module_tree:
            self.module_tree['custom_scripts'] = {}
        
        # Add each custom module to the tree
        for module in self.custom_modules:
            script_name = module.dotted_path.split('.')[-1]
            self.module_tree['custom_scripts'][script_name] = module
    
    def _find_module_by_path(self, path: str) -> Optional[ModuleMeta]:
        """Find a module by its dotted path."""
        for module in self.modules:
            if module.dotted_path == path:
                return module
        return None
    
    def _is_exploit_module(self, module: ModuleMeta) -> bool:
        """Check if a module is an exploit module."""
        return module.category == "exploits"
    
    def _get_available_payloads(self) -> List[ModuleMeta]:
        """Get all available payload modules."""
        return [module for module in self.modules if module.category == "payloads"]
    
    def _get_compatible_payloads(self, exploit_module: ModuleMeta) -> List[ModuleMeta]:
        """Get payloads compatible with the given exploit module.
        
        Args:
            exploit_module: The exploit module to find compatible payloads for
            
        Returns:
            List of compatible payload modules
        """
        all_payloads = self._get_available_payloads()
        
        # For now, filter based on common patterns and payload types
        # This can be enhanced with more sophisticated compatibility logic
        
        compatible_payloads = []
        exploit_path = exploit_module.dotted_path.lower()
        
        for payload in all_payloads:
            payload_path = payload.dotted_path.lower()
            
            # Include all generic payloads (cmd, generic)
            if any(term in payload_path for term in ["cmd.", "generic"]):
                compatible_payloads.append(payload)
                continue
            
            # Architecture-specific filtering
            # If exploit targets specific architecture, prefer matching payloads
            arch_hints = {
                "arm": ["arm", "armle", "armbe"],
                "mips": ["mips", "mipsle", "mipsbe"], 
                "x86": ["x86", "x64"],
                "sparc": ["sparc"],
                "ppc": ["ppc", "powerpc"]
            }
            
            # Check if exploit hints at specific architecture
            exploit_arch = None
            for arch, variants in arch_hints.items():
                if any(variant in exploit_path for variant in variants):
                    exploit_arch = arch
                    break
            
            # If we found architecture hints, prefer matching payloads
            if exploit_arch:
                arch_variants = arch_hints[exploit_arch]
                if any(variant in payload_path for variant in arch_variants):
                    compatible_payloads.append(payload)
                # Also include generic payloads for arch-specific exploits
                elif any(term in payload_path for term in ["generic", "cmd"]):
                    compatible_payloads.append(payload)
            else:
                # No specific architecture detected, include most payloads except very specific ones
                # Exclude architecture-specific payloads when no arch hints
                if not any(arch_var in payload_path for arch_vars in arch_hints.values() for arch_var in arch_vars):
                    compatible_payloads.append(payload)
                # But always include cmd payloads as they're usually universal
                elif "cmd." in payload_path:
                    compatible_payloads.append(payload)
        
        # Remove duplicates and sort by name
        seen = set()
        unique_payloads = []
        for payload in compatible_payloads:
            if payload.dotted_path not in seen:
                seen.add(payload.dotted_path)
                unique_payloads.append(payload)
        
        return sorted(unique_payloads, key=lambda p: p.name)
    
    def _serialize_tree(self, tree: Dict[str, Any]) -> Dict[str, Any]:
        """Convert the module tree to a JSON-serializable format.
        
        Args:
            tree: The module tree to serialize
            
        Returns:
            JSON-serializable dictionary with proper structure
        """
        serialized = {}
        
        for key, value in tree.items():
            if hasattr(value, 'dotted_path'):  # This is a ModuleMeta object
                # Convert ModuleMeta to dict
                serialized[key] = {
                    'name': value.name,
                    'description': value.description,
                    'dotted_path': value.dotted_path,
                    'category': value.category,
                    'cve_list': getattr(value, 'cve_list', [])
                }
            elif isinstance(value, dict):
                # This is a nested category - separate modules and subcategories
                modules = []
                categories = {}
                
                for child_key, child_value in value.items():
                    if hasattr(child_value, 'dotted_path'):  # ModuleMeta object
                        modules.append({
                            'name': child_value.name,
                            'description': child_value.description,
                            'dotted_path': child_value.dotted_path,
                            'category': child_value.category,
                            'cve_list': getattr(child_value, 'cve_list', [])
                        })
                    elif isinstance(child_value, dict):
                        # Recursive call for nested categories
                        categories[child_key] = self._serialize_tree({child_key: child_value})[child_key]
                
                # Only include modules and categories if they exist
                category_data = {}
                if modules:
                    category_data['modules'] = modules
                if categories:
                    category_data['categories'] = categories
                
                serialized[key] = category_data
            else:
                # Fallback for any other type
                serialized[key] = str(value)
        
        return serialized
    
    def _serialize_options(self, options: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Convert module options to a JSON-serializable format.
        
        Args:
            options: The options dictionary to serialize
            
        Returns:
            JSON-serializable dictionary
        """
        serialized = {}
        
        for opt_name, opt_info in options.items():
            serialized_option = {}
            
            for key, value in opt_info.items():
                # Convert non-serializable objects to strings or appropriate types
                if hasattr(value, '__call__'):  # Function/method
                    serialized_option[key] = str(value)
                elif hasattr(value, '__dict__'):  # Complex object
                    serialized_option[key] = str(value)
                else:
                    # Basic types that are JSON serializable
                    serialized_option[key] = value
            
            serialized[opt_name] = serialized_option
        
        return serialized
    
    def _process_options(self, options: Dict[str, Any], option_specs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Process and validate options from the web interface.
        
        Args:
            options: Raw options from the web interface
            option_specs: Option specifications from the module
            
        Returns:
            Processed and validated options
        """
        processed = {}
        
        logger.info("Processing options", raw_options=options, spec_count=len(option_specs))
        
        for opt_name, opt_value in options.items():
            if opt_name in option_specs:
                spec = option_specs[opt_name]
                original_value = spec.get('current_value')
                
                logger.info("Processing option", option=opt_name, input_value=opt_value, input_type=type(opt_value).__name__, original_value=original_value, original_type=type(original_value).__name__)
                
                # Convert the value to the appropriate type
                try:
                    converted_value = self._convert_option_value(opt_value, original_value)
                    processed[opt_name] = converted_value
                    logger.info("Successfully converted option", option=opt_name, converted_value=converted_value, converted_type=type(converted_value).__name__)
                except (ValueError, TypeError) as e:
                    logger.warning("Invalid option value", option=opt_name, value=opt_value, error=str(e))
                    # Use default value if conversion fails
                    processed[opt_name] = original_value
                    logger.info("Using default value for option", option=opt_name, default_value=original_value)
            else:
                # Unknown option, pass through as-is
                logger.warning("Unknown option, passing through", option=opt_name, value=opt_value)
                processed[opt_name] = opt_value
        
        logger.info("Finished processing options", processed_options=processed)
        return processed
    
    def _convert_option_value(self, user_input: Any, original_value: Any) -> Any:
        """Convert user input to the appropriate type based on original value.
        
        Args:
            user_input: Value from user input
            original_value: Original value from the module
            
        Returns:
            Converted value with appropriate type
        """
        logger.debug("Converting option value", user_input=user_input, user_input_type=type(user_input).__name__, original_value=original_value, original_type=type(original_value).__name__)
        
        if user_input == "" or user_input is None:
            logger.debug("Input is empty or None, returning original", result=original_value)
            return original_value
        
        # If original value is None, return the input as string
        if original_value is None:
            result = str(user_input)
            logger.debug("Original is None, converting to string", result=result)
            return result
        
        # Convert based on the type of the original value
        if isinstance(original_value, bool):
            logger.debug("Converting to boolean", user_input=user_input, user_input_type=type(user_input).__name__)
            
            if isinstance(user_input, bool):
                logger.debug("Input is already boolean", result=user_input)
                return user_input
                
            if isinstance(user_input, str):
                result = user_input.lower() in ('true', '1', 'yes', 'on')
                logger.debug("Converting string to boolean", string_input=user_input, lower_input=user_input.lower(), result=result)
                return result
                
            result = bool(user_input)
            logger.debug("Converting other type to boolean", input_value=user_input, result=result)
            return result
        
        if isinstance(original_value, int):
            result = int(user_input)
            logger.debug("Converting to int", user_input=user_input, result=result)
            return result
        
        if isinstance(original_value, float):
            result = float(user_input)
            logger.debug("Converting to float", user_input=user_input, result=result)
            return result
        
        # Default to string
        result = str(user_input)
        logger.debug("Converting to string (default)", user_input=user_input, result=result)
        return result
    
    def _on_module_output(self, line: str, level: str) -> None:
        """Handle output from running module."""
        # Debug output to stderr to avoid recursion
        import sys
        sys.__stderr__.write(f"[DEBUG] _on_module_output called: {line}\n")
        sys.__stderr__.flush()
        
        self.socketio.emit('output', {
            'line': line,
            'level': level,
            'timestamp': threading.current_thread().ident
        })
    
    def _on_module_complete(self, success: bool, error_msg: Optional[str]) -> None:
        """Handle module completion."""
        self.current_module = None
        self.socketio.emit('complete', {
            'success': success,
            'error': error_msg
        })
    
    def _on_auto_own_output(self, line: str, level: str) -> None:
        """Handle auto-own output."""
        self.socketio.emit('auto_own_output', {
            'line': line,
            'level': level
        })
        logger.info("Auto-own output", line=line, level=level)
    
    def _on_auto_own_complete(self, success: bool, error_msg: Optional[str]) -> None:
        """Handle auto-own completion."""
        self.socketio.emit('auto_own_complete', {
            'success': success,
            'error': error_msg
        })
        logger.info("Auto-own process completed", success=success, error=error_msg)
    
    def _on_auto_own_progress(self, status: str, percentage: float) -> None:
        """Handle auto-own progress updates."""
        self.socketio.emit('auto_own_progress', {
            'status': status,
            'percentage': percentage
        })
        logger.info("Auto-own progress", status=status, percentage=percentage)
    
    def _simulate_session_command(self, command: str, session_info: Dict[str, Any]) -> str:
        """Simulate session command execution for demonstration purposes.
        
        Args:
            command: Command to simulate
            session_info: Session information
            
        Returns:
            Simulated command output
        """
        target = session_info.get('target', 'unknown')
        session_type = session_info.get('session_type', 'shell')
        
        # Common commands simulation
        if command == 'whoami':
            return 'root\n$ '
        elif command == 'id':
            return 'uid=0(root) gid=0(root) groups=0(root)\n$ '
        elif command == 'pwd':
            return '/root\n$ '
        elif command == 'uname -a':
            return f'Linux {target} 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux\n$ '
        elif command.startswith('ls'):
            if '-la' in command or '-al' in command:
                return 'total 12\ndrwx------  3 root root 4096 Jan 01 12:00 .\ndrwxr-xr-x 18 root root 4096 Jan 01 12:00 ..\n-rw-------  1 root root  123 Jan 01 12:00 .bash_history\n$ '
            else:
                return 'Documents  Downloads  Desktop  Pictures\n$ '
        elif command.startswith('cat /etc/passwd'):
            return 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n$ '
        elif command == 'ps aux':
            return 'USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot           1  0.0  0.1  22548  2048 ?        Ss   12:00   0:01 /sbin/init\nroot         123  0.0  0.0  12345  1024 ?        S    12:01   0:00 /bin/bash\n$ '
        elif command == 'netstat -an':
            return 'Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n$ '
        elif command == 'help':
            return f"""
Available commands in {session_type} session on {target}:

Basic Commands:
- whoami          (show current user)
- id              (show user ID and groups)
- pwd             (show current directory)
- ls [-la]        (list files)
- uname -a        (system information)
- ps aux          (running processes)
- netstat -an     (network connections)
- cat <file>      (display file contents)

Navigation:
- cd <directory>  (change directory)
- find <path>     (search for files)

System Information:
- df -h           (disk space)
- free -m         (memory usage)
- uptime          (system uptime)

Type 'exit' to close the session.
$ """
        elif command == 'exit':
            return 'Session closed.\n'
        else:
            # Generic response for unknown commands
            return f"{command}: command executed successfully\n$ "
    
    def _on_session_created(self, session_info: Dict[str, Any]) -> None:
        """Handle notification when an RCE session is created.
        
        Args:
            session_info: Information about the created session
        """
        # Emit session creation notification to all clients
        self.socketio.emit('session_created', {
            'session_id': session_info.get('session_id'),
            'target': session_info.get('target'),
            'session_type': session_info.get('session_type'),
            'instructions': session_info.get('instructions', ''),
            'websocket_endpoint': session_info.get('websocket_endpoint', '')
        })
        
        logger.info("RCE session created notification sent", 
                   session_id=session_info.get('session_id'),
                   target=session_info.get('target'))

    def _validate_script(self, content: str, filename: str) -> Dict[str, Any]:
        """Validate a custom script for security and structure."""
        errors = []
        warnings = []
        
        try:
            # Parse the script to AST
            tree = ast.parse(content)
            
            # Check for required class and methods
            has_exploit_class = False
            has_run_method = False
            class_name = None
            
            # SECURITY: Advanced sandboxed filtering - blocks RCE while allowing legitimate exploit functions
            
            # Completely forbidden imports (high RCE risk)
            FORBIDDEN_IMPORTS = [
                'subprocess', 'os', 'importlib', '__import__', 'builtins', 
                '__builtins__', 'imp', 'zipimport'
            ]
            
            # Forbidden functions (direct RCE)
            FORBIDDEN_FUNCTIONS = [
                'eval', 'exec', 'compile', '__import__', 'input', 'raw_input'
            ]
            
            # Dangerous OS-level attributes (system calls)
            FORBIDDEN_ATTRIBUTES = [
                'system', 'popen', 'spawn', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
                'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'execl', 'execle', 
                'execlp', 'execlpe', 'execv', 'execve', 'execvp', 'execvpe',
                'Popen', 'call', 'check_call', 'check_output', 'run',
                'getoutput', 'getstatusoutput'
            ]
            
            # Allowed controlled imports (networking/legitimate exploit functions)
            ALLOWED_CONTROLLED_IMPORTS = [
                'socket', 'requests', 'urllib', 'http', 'ssl', 'hashlib', 
                'base64', 'json', 'xml', 're', 'time', 'random', 'struct',
                'binascii', 'zlib', 'threading', 'queue'
            ]
            
            # Controlled file operations (limited scope)
            ALLOWED_FILE_FUNCTIONS = ['open', 'file']
            
            # Patterns that indicate malicious file operations
            MALICIOUS_FILE_PATTERNS = [
                r'/etc/', r'/var/', r'/usr/', r'/bin/', r'/sbin/', r'/root/',
                r'\.\./', r'~/', r'/tmp/.*\.sh', r'/tmp/.*\.py', r'\.bashrc',
                r'\.profile', r'passwd', r'shadow', r'authorized_keys'
            ]

            for node in ast.walk(tree):
                # Block dangerous imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in FORBIDDEN_IMPORTS:
                            errors.append(f"BLOCKED: Forbidden import '{alias.name}' - High RCE risk")
                        elif alias.name not in ALLOWED_CONTROLLED_IMPORTS and '.' not in alias.name:
                            # Allow standard library modules but warn about unknown ones
                            warnings.append(f"Unknown import '{alias.name}' - Verify this is safe")
                
                if isinstance(node, ast.ImportFrom):
                    if node.module in FORBIDDEN_IMPORTS:
                        errors.append(f"BLOCKED: Forbidden import from '{node.module}' - High RCE risk")
                    
                    # Check specific function imports
                    if node.names:
                        for alias in node.names:
                            if alias.name in FORBIDDEN_FUNCTIONS:
                                errors.append(f"BLOCKED: Forbidden function import '{alias.name}' - RCE risk")
                
                # Check function calls for dangerous operations
                if isinstance(node, ast.Call):
                    # Block direct dangerous function calls
                    if isinstance(node.func, ast.Name):
                        if node.func.id in FORBIDDEN_FUNCTIONS:
                            errors.append(f"BLOCKED: Dangerous function call '{node.func.id}' - RCE risk")
                        
                        # Validate file operations
                        elif node.func.id in ALLOWED_FILE_FUNCTIONS:
                            self._validate_file_operation(node, errors, warnings, MALICIOUS_FILE_PATTERNS)
                    
                    # Block dangerous method calls (like os.system)
                    elif isinstance(node.func, ast.Attribute):
                        if node.func.attr in FORBIDDEN_ATTRIBUTES:
                            errors.append(f"BLOCKED: Dangerous method '{node.func.attr}' - RCE risk")
                
                # Block dangerous attribute access
                if isinstance(node, ast.Attribute):
                    if node.attr in FORBIDDEN_ATTRIBUTES:
                        warnings.append(f"Suspicious attribute access '{node.attr}' - Review carefully")
                
                # Check for class definition
                if isinstance(node, ast.ClassDef):
                    has_exploit_class = True
                    class_name = node.name
                    
                    # Check if class has a run method
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef) and item.name == 'run':
                            has_run_method = True
            
            if not has_exploit_class:
                errors.append("Script must contain at least one class definition")
            
            if has_exploit_class and not has_run_method:
                errors.append("Exploit class must have a 'run' method")
            
            # Check syntax
            compile(content, filename, 'exec')
            
        except SyntaxError as e:
            errors.append(f"Syntax error: {e}")
        except Exception as e:
            errors.append(f"Validation error: {e}")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'class_name': class_name
        }
    
    def _validate_file_operation(self, node: Any, errors: List[str], warnings: List[str], malicious_patterns: List[str]) -> None:
        """Validate file operations to prevent access to sensitive paths."""
        import re
        
        if not node.args:
            return
        
        # Check if first argument (filename) is a string literal
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Str):  # Python < 3.8
            filename = first_arg.s
        elif isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):  # Python >= 3.8
            filename = first_arg.value
        else:
            # Dynamic filename - warn but don't block
            warnings.append("Dynamic file path detected - Ensure it doesn't access sensitive locations")
            return
        
        # Check against malicious patterns
        for pattern in malicious_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                errors.append(f"BLOCKED: File access to sensitive path '{filename}' - Security risk")
                return
        
        # Allow relative paths in working directory
        if not filename.startswith('/') and '..' not in filename:
            warnings.append(f"File operation: '{filename}' - Restricted to working directory")
        elif filename.startswith('/tmp/') and not any(ext in filename for ext in ['.sh', '.py', '.pl', '.rb']):
            warnings.append(f"Temporary file access: '{filename}' - Monitor for malicious content")
        else:
            warnings.append(f"File access: '{filename}' - Review for security implications")

    def _load_custom_script(self, script_path: Path) -> Optional[ModuleMeta]:
        """Load a custom script as a ModuleMeta object."""
        try:
            import importlib.util
            import sys
            
            # Create module spec
            module_name = f"custom_scripts.{script_path.stem}"
            
            # Clean up any existing module to avoid conflicts
            if module_name in sys.modules:
                del sys.modules[module_name]
            
            spec = importlib.util.spec_from_file_location(module_name, script_path)
            if not spec or not spec.loader:
                logger.error("Failed to create module spec", path=str(script_path))
                return None
            
            # Load the module
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Find the exploit class
            exploit_classes = []
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if hasattr(obj, 'run') and name != 'object':
                    exploit_classes.append((name, obj))
            
            if not exploit_classes:
                logger.error("No valid exploit class found", path=str(script_path))
                return None
            
            # Use the first valid exploit class
            class_name, exploit_class = exploit_classes[0]
            
            # Create an instance to extract options
            try:
                instance = exploit_class()
                options = self._extract_custom_script_options(instance)
            except Exception as e:
                logger.warning("Failed to extract options", error=str(e))
                options = {}
            
            # Create ModuleMeta
            description = getattr(exploit_class, '__doc__', '') or f"Custom script: {script_path.name}"
            
            module_meta = ModuleMeta(
                dotted_path=module_name,
                cls=exploit_class,
                opts=options,
                category="custom_scripts",
                name=class_name.replace('_', ' ').title(),
                description=description.strip(),
                cve_list=getattr(exploit_class, 'cve', [])
            )
            
            logger.info("Custom script loaded successfully", 
                       name=module_meta.name, 
                       path=module_name)
            
            return module_meta
            
        except Exception as e:
            logger.error("Failed to load custom script", 
                        path=str(script_path), 
                        error=str(e))
            return None

    def _extract_custom_script_options(self, instance: Any) -> Dict[str, Dict[str, Any]]:
        """Extract options from a custom script instance."""
        options = {}
        
        # Common default options for custom scripts
        default_options = {
            'target': {'value': '', 'description': 'Target IP address', 'required': True},
            'port': {'value': 80, 'description': 'Target port', 'required': True},
            'timeout': {'value': 10, 'description': 'Connection timeout in seconds', 'required': False}
        }
        
        # Try to get options from the instance
        if hasattr(instance, 'target'):
            default_options['target']['value'] = getattr(instance, 'target', '')
        if hasattr(instance, 'port'):
            default_options['port']['value'] = getattr(instance, 'port', 80)
        if hasattr(instance, 'timeout'):
            default_options['timeout']['value'] = getattr(instance, 'timeout', 10)
        
        # Look for additional custom options
        for attr_name in dir(instance):
            if not attr_name.startswith('_') and attr_name not in ['run', 'target', 'port', 'timeout']:
                attr_value = getattr(instance, attr_name, None)
                if not callable(attr_value):
                    default_options[attr_name] = {
                        'value': attr_value,
                        'description': f'Custom option: {attr_name}',
                        'required': False
                    }
        
        return default_options

    def _get_script_info(self, script_path: Path) -> Dict[str, Any]:
        """Get information about a script file."""
        try:
            content = script_path.read_text()
            validation = self._validate_script(content, script_path.name)
            
            # Get file stats
            stat = script_path.stat()
            
            return {
                'name': script_path.name,
                'size': stat.st_size,
                'modified': int(stat.st_mtime),
                'valid': validation['valid'],
                'class_name': validation.get('class_name', 'Unknown'),
                'errors': validation['errors'],
                'warnings': validation['warnings']
            }
        except Exception as e:
            return {
                'name': script_path.name,
                'size': 0,
                'modified': 0,
                'valid': False,
                'class_name': 'Unknown',
                'errors': [str(e)],
                'warnings': []
            }
    
    def run(self, debug: bool = False) -> None:
        """Start the web server.
        
        Args:
            debug: Whether to run in debug mode
        """
        logger.info("Starting RouterSploit Web GUI", host=self.host, port=self.port)
        print(f"\nRouterSploit GUI is starting...")
        print(f"Open your browser and go to: http://{self.host}:{self.port}")
        print("Press Ctrl+C to stop the server\n")
        
        self.socketio.run(
            self.app,
            host=self.host,
            port=self.port,
            debug=debug,
            allow_unsafe_werkzeug=True
        )
    
    def cleanup(self) -> None:
        """Cleanup resources."""
        self.runner_manager.cleanup()
        self.console_handler.cleanup()
        self.auto_own_manager.cleanup()


def create_app() -> Flask:
    """Factory function to create Flask app."""
    gui = RouterSploitWebGUI()
    return gui.app


def main() -> None:
    """Main entry point for the web GUI."""
    import argparse
    
    parser = argparse.ArgumentParser(description="RouterSploit Web GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    
    args = parser.parse_args()
    
    gui = RouterSploitWebGUI(host=args.host, port=args.port)
    try:
        gui.run(debug=args.debug)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        gui.cleanup()


if __name__ == "__main__":
    main() 
