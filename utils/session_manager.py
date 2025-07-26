"""
Session Manager - Manage VAPT assessment sessions
Handles session creation, persistence, and recovery for VAPT assessments
"""

import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from colorama import Fore, Style

class SessionManager:
    def __init__(self, sessions_dir="./vapt_sessions"):
        self.sessions_dir = sessions_dir
        self.ensure_sessions_directory()
        self.current_session = None
        
    def ensure_sessions_directory(self):
        """Ensure the sessions directory exists"""
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir, exist_ok=True)
            
    def create_session(self, vapt_type: str, target: str, config: Optional[Dict] = None) -> Dict:
        """Create a new VAPT session"""
        session_id = self.generate_session_id(vapt_type)
        timestamp = datetime.now()
        
        session = {
            'id': session_id,
            'type': vapt_type,
            'target': target,
            'status': 'created',
            'created_at': timestamp.isoformat(),
            'updated_at': timestamp.isoformat(),
            'start_time': timestamp.isoformat(),
            'end_time': None,
            'duration': None,
            'phases_completed': [],
            'current_phase': None,
            'findings': [],
            'tools_used': [],
            'configuration': config or {},
            'metadata': {
                'version': '1.0',
                'created_by': 'VAPT Automated Tool',
                'platform': os.name,
                'working_directory': os.getcwd()
            },
            'phase_data': {},
            'error_log': [],
            'session_notes': []
        }
        
        # Create session directory
        session_path = self.get_session_path(session_id)
        os.makedirs(session_path, exist_ok=True)
        
        # Save session
        self.save_session(session)
        self.current_session = session
        
        return session
        
    def generate_session_id(self, vapt_type: str) -> str:
        """Generate a unique session ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_suffix = str(uuid.uuid4())[:8]
        return f"{vapt_type}_{timestamp}_{unique_suffix}"
        
    def get_session_path(self, session_id: str) -> str:
        """Get the full path for a session directory"""
        return os.path.join(self.sessions_dir, session_id)
        
    def get_session_file_path(self, session_id: str) -> str:
        """Get the full path for a session metadata file"""
        return os.path.join(self.get_session_path(session_id), "session.json")
        
    def save_session(self, session: Dict) -> bool:
        """Save session data to disk"""
        try:
            session['updated_at'] = datetime.now().isoformat()
            session_file = self.get_session_file_path(session['id'])
            
            # Ensure session directory exists
            os.makedirs(os.path.dirname(session_file), exist_ok=True)
            
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(session, f, indent=2, default=str)
                
            return True
            
        except Exception as e:
            print(f"{Fore.RED}Error saving session: {str(e)}{Style.RESET_ALL}")
            return False
            
    def load_session(self, session_id: str) -> Optional[Dict]:
        """Load session data from disk"""
        try:
            session_file = self.get_session_file_path(session_id)
            
            if not os.path.exists(session_file):
                return None
                
            with open(session_file, 'r', encoding='utf-8') as f:
                session = json.load(f)
                
            self.current_session = session
            return session
            
        except Exception as e:
            print(f"{Fore.RED}Error loading session {session_id}: {str(e)}{Style.RESET_ALL}")
            return None
            
    def list_sessions(self, vapt_type: Optional[str] = None, status: Optional[str] = None) -> List[Dict]:
        """List all sessions, optionally filtered by type and status"""
        sessions = []
        
        try:
            if not os.path.exists(self.sessions_dir):
                return sessions
                
            for session_dir in os.listdir(self.sessions_dir):
                session_path = os.path.join(self.sessions_dir, session_dir)
                
                if not os.path.isdir(session_path):
                    continue
                    
                session_file = os.path.join(session_path, "session.json")
                
                if not os.path.exists(session_file):
                    continue
                    
                try:
                    with open(session_file, 'r', encoding='utf-8') as f:
                        session = json.load(f)
                        
                    # Apply filters
                    if vapt_type and session.get('type') != vapt_type:
                        continue
                        
                    if status and session.get('status') != status:
                        continue
                        
                    sessions.append(session)
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}Warning: Could not load session from {session_file}: {str(e)}{Style.RESET_ALL}")
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}Error listing sessions: {str(e)}{Style.RESET_ALL}")
            
        # Sort by creation time (newest first)
        sessions.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return sessions
        
    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its data"""
        try:
            import shutil
            
            session_path = self.get_session_path(session_id)
            
            if os.path.exists(session_path):
                shutil.rmtree(session_path)
                
            if self.current_session and self.current_session.get('id') == session_id:
                self.current_session = None
                
            return True
            
        except Exception as e:
            print(f"{Fore.RED}Error deleting session {session_id}: {str(e)}{Style.RESET_ALL}")
            return False
            
    def update_session_status(self, session_id: str, status: str, notes: Optional[str] = None) -> bool:
        """Update session status"""
        session = self.load_session(session_id)
        
        if not session:
            return False
            
        session['status'] = status
        session['updated_at'] = datetime.now().isoformat()
        
        if status in ['completed', 'failed', 'cancelled']:
            session['end_time'] = datetime.now().isoformat()
            
            # Calculate duration
            if session.get('start_time'):
                try:
                    start_time = datetime.fromisoformat(session['start_time'].replace('Z', '+00:00'))
                    end_time = datetime.now()
                    duration = (end_time - start_time).total_seconds()
                    session['duration'] = duration
                except Exception:
                    pass
                    
        if notes:
            session['session_notes'].append({
                'timestamp': datetime.now().isoformat(),
                'note': notes
            })
            
        return self.save_session(session)
        
    def add_phase_completion(self, session_id: str, phase_name: str, phase_data: Optional[Dict] = None) -> bool:
        """Mark a phase as completed and store its data"""
        session = self.load_session(session_id)
        
        if not session:
            return False
            
        if phase_name not in session['phases_completed']:
            session['phases_completed'].append(phase_name)
            
        session['current_phase'] = phase_name
        
        if phase_data:
            session['phase_data'][phase_name] = phase_data
            
        return self.save_session(session)
        
    def add_finding(self, session_id: str, finding: Dict) -> bool:
        """Add a finding to the session"""
        session = self.load_session(session_id)
        
        if not session:
            return False
            
        finding['id'] = str(uuid.uuid4())
        finding['timestamp'] = datetime.now().isoformat()
        
        session['findings'].append(finding)
        
        return self.save_session(session)
        
    def add_tool_usage(self, session_id: str, tool_name: str, tool_data: Optional[Dict] = None) -> bool:
        """Record tool usage in the session"""
        session = self.load_session(session_id)
        
        if not session:
            return False
            
        tool_entry = {
            'tool': tool_name,
            'timestamp': datetime.now().isoformat()
        }
        
        if tool_data:
            tool_entry.update(tool_data)
            
        if tool_name not in [t.get('tool') for t in session['tools_used']]:
            session['tools_used'].append(tool_entry)
        else:
            # Update existing entry
            for i, existing_tool in enumerate(session['tools_used']):
                if existing_tool.get('tool') == tool_name:
                    session['tools_used'][i] = tool_entry
                    break
                    
        return self.save_session(session)
        
    def log_error(self, session_id: str, error_message: str, error_context: Optional[Dict] = None) -> bool:
        """Log an error in the session"""
        session = self.load_session(session_id)
        
        if not session:
            return False
            
        error_entry = {
            'timestamp': datetime.now().isoformat(),
            'message': error_message,
            'context': error_context or {}
        }
        
        session['error_log'].append(error_entry)
        
        return self.save_session(session)
        
    def get_session_summary(self, session_id: str) -> Optional[Dict]:
        """Get a summary of session data"""
        session = self.load_session(session_id)
        
        if not session:
            return None
            
        summary = {
            'id': session['id'],
            'type': session['type'],
            'target': session['target'],
            'status': session['status'],
            'created_at': session['created_at'],
            'duration': session.get('duration'),
            'phases_completed': len(session['phases_completed']),
            'total_phases': self.get_total_phases_for_vapt_type(session['type']),
            'findings_count': len(session['findings']),
            'tools_used_count': len(session['tools_used']),
            'errors_count': len(session['error_log']),
            'completion_percentage': self.calculate_completion_percentage(session)
        }
        
        # Categorize findings by severity
        findings_by_severity = {}
        for finding in session['findings']:
            severity = finding.get('severity', 'Unknown').lower()
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
            
        summary['findings_by_severity'] = findings_by_severity
        
        return summary
        
    def get_total_phases_for_vapt_type(self, vapt_type: str) -> int:
        """Get total number of phases for a VAPT type"""
        phase_counts = {
            'network': 5,
            'web': 5,
            'cloud': 5,
            'api': 5
        }
        return phase_counts.get(vapt_type, 5)
        
    def calculate_completion_percentage(self, session: Dict) -> float:
        """Calculate completion percentage of a session"""
        total_phases = self.get_total_phases_for_vapt_type(session['type'])
        completed_phases = len(session['phases_completed'])
        
        if total_phases == 0:
            return 100.0
            
        return (completed_phases / total_phases) * 100.0
        
    def export_session(self, session_id: str, export_path: str, format: str = 'json') -> bool:
        """Export session data to a file"""
        session = self.load_session(session_id)
        
        if not session:
            return False
            
        try:
            if format.lower() == 'json':
                with open(export_path, 'w', encoding='utf-8') as f:
                    json.dump(session, f, indent=2, default=str)
            else:
                return False
                
            return True
            
        except Exception as e:
            print(f"{Fore.RED}Error exporting session: {str(e)}{Style.RESET_ALL}")
            return False
            
    def import_session(self, import_path: str) -> Optional[str]:
        """Import session data from a file"""
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                session = json.load(f)
                
            # Generate new session ID to avoid conflicts
            old_id = session['id']
            session['id'] = self.generate_session_id(session['type'])
            session['imported_at'] = datetime.now().isoformat()
            session['imported_from'] = old_id
            
            # Save imported session
            if self.save_session(session):
                return session['id']
            else:
                return None
                
        except Exception as e:
            print(f"{Fore.RED}Error importing session: {str(e)}{Style.RESET_ALL}")
            return None
            
    def cleanup_old_sessions(self, days_old: int = 30) -> int:
        """Clean up sessions older than specified days"""
        cleaned_count = 0
        cutoff_date = datetime.now().timestamp() - (days_old * 24 * 60 * 60)
        
        sessions = self.list_sessions()
        
        for session in sessions:
            try:
                created_at = datetime.fromisoformat(session['created_at'].replace('Z', '+00:00'))
                
                if created_at.timestamp() < cutoff_date:
                    if self.delete_session(session['id']):
                        cleaned_count += 1
                        
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not process session {session['id']}: {str(e)}{Style.RESET_ALL}")
                
        return cleaned_count
        
    def get_session_statistics(self) -> Dict:
        """Get overall statistics for all sessions"""
        sessions = self.list_sessions()
        
        stats = {
            'total_sessions': len(sessions),
            'sessions_by_type': {},
            'sessions_by_status': {},
            'total_findings': 0,
            'findings_by_severity': {},
            'most_used_tools': {},
            'average_duration': 0,
            'success_rate': 0
        }
        
        total_duration = 0
        duration_count = 0
        successful_sessions = 0
        
        for session in sessions:
            # Count by type
            vapt_type = session.get('type', 'unknown')
            stats['sessions_by_type'][vapt_type] = stats['sessions_by_type'].get(vapt_type, 0) + 1
            
            # Count by status
            status = session.get('status', 'unknown')
            stats['sessions_by_status'][status] = stats['sessions_by_status'].get(status, 0) + 1
            
            # Count findings
            findings = session.get('findings', [])
            stats['total_findings'] += len(findings)
            
            for finding in findings:
                severity = finding.get('severity', 'Unknown').lower()
                stats['findings_by_severity'][severity] = stats['findings_by_severity'].get(severity, 0) + 1
                
            # Count tool usage
            for tool_entry in session.get('tools_used', []):
                tool_name = tool_entry.get('tool', 'unknown')
                stats['most_used_tools'][tool_name] = stats['most_used_tools'].get(tool_name, 0) + 1
                
            # Calculate duration
            if session.get('duration'):
                total_duration += session['duration']
                duration_count += 1
                
            # Count successful sessions
            if status in ['completed']:
                successful_sessions += 1
                
        # Calculate averages and rates
        if duration_count > 0:
            stats['average_duration'] = total_duration / duration_count
            
        if len(sessions) > 0:
            stats['success_rate'] = (successful_sessions / len(sessions)) * 100
            
        return stats
        
    def resume_session(self, session_id: str) -> Optional[Dict]:
        """Resume a previously interrupted session"""
        session = self.load_session(session_id)
        
        if not session:
            return None
            
        # Update status if it was interrupted
        if session.get('status') in ['running', 'created']:
            session['status'] = 'resumed'
            session['resumed_at'] = datetime.now().isoformat()
            self.save_session(session)
            
        self.current_session = session
        return session
        
    def backup_sessions(self, backup_path: str) -> bool:
        """Create a backup of all sessions"""
        try:
            import shutil
            
            if os.path.exists(self.sessions_dir):
                shutil.copytree(self.sessions_dir, backup_path)
                return True
            else:
                return False
                
        except Exception as e:
            print(f"{Fore.RED}Error backing up sessions: {str(e)}{Style.RESET_ALL}")
            return False
            
    def restore_sessions(self, backup_path: str) -> bool:
        """Restore sessions from a backup"""
        try:
            import shutil
            
            if os.path.exists(backup_path):
                # Remove existing sessions directory
                if os.path.exists(self.sessions_dir):
                    shutil.rmtree(self.sessions_dir)
                    
                # Restore from backup
                shutil.copytree(backup_path, self.sessions_dir)
                return True
            else:
                return False
                
        except Exception as e:
            print(f"{Fore.RED}Error restoring sessions: {str(e)}{Style.RESET_ALL}")
            return False
