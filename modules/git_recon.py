#!/usr/bin/env python3
"""
Git Reconnaissance Module for Elbanna Recon v1.0

This module provides comprehensive Git platform reconnaissance and analysis.
Features:
- GitHub public repository enumeration
- Repository metadata extraction (stars, forks, languages, topics)
- Recent commit activity analysis
- User profile information gathering
- Rate limit handling with optional API authentication
- Security-focused analysis of exposed repositories

Author: Yousef Osama
"""

import os
import time
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from urllib.parse import urljoin

# Try to import requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class GitRecon:
    """
    Git platform reconnaissance and analysis engine.
    """
    
    # API endpoints for different platforms
    GITHUB_API_BASE = "https://api.github.com"
    
    # User agent for requests
    USER_AGENT = "Elbanna-Recon-v1.0-GitRecon"
    
    # Request timeout settings
    DEFAULT_TIMEOUT = 15
    
    # Rate limit information
    GITHUB_RATE_LIMIT = {
        'unauthenticated': 60,  # requests per hour
        'authenticated': 5000   # requests per hour
    }
    
    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        """
        Initialize the Git reconnaissance engine.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = None
        self.github_token = None
        
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': self.USER_AGENT,
                'Accept': 'application/vnd.github.v3+json'
            })
            
            # Check for GitHub token in environment
            self.github_token = os.environ.get('GITHUB_TOKEN')
            if self.github_token:
                self.session.headers.update({
                    'Authorization': f'token {self.github_token}'
                })
    
    def check_rate_limit(self, platform: str = "github") -> Dict[str, Any]:
        """
        Check current rate limit status.
        
        Args:
            platform: Platform to check (currently only GitHub)
            
        Returns:
            Rate limit information
        """
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests library not available'}
        
        if platform.lower() != "github":
            return {'error': f'Platform {platform} not supported yet'}
        
        try:
            response = self.session.get(
                f"{self.GITHUB_API_BASE}/rate_limit",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                core_limits = data.get('resources', {}).get('core', {})
                
                return {
                    'remaining': core_limits.get('remaining', 0),
                    'limit': core_limits.get('limit', 0),
                    'reset_time': core_limits.get('reset', 0),
                    'reset_datetime': datetime.fromtimestamp(core_limits.get('reset', 0)).isoformat(),
                    'authenticated': bool(self.github_token),
                    'rate_limit_type': 'authenticated' if self.github_token else 'unauthenticated'
                }
            else:
                return {
                    'error': f'Failed to check rate limit: {response.status_code}',
                    'authenticated': bool(self.github_token)
                }
                
        except Exception as e:
            return {
                'error': f'Rate limit check failed: {str(e)}',
                'authenticated': bool(self.github_token)
            }
    
    def get_github_user_info(self, username: str) -> Dict[str, Any]:
        """
        Get GitHub user profile information.
        
        Args:
            username: GitHub username
            
        Returns:
            User profile information
        """
        try:
            response = self.session.get(
                f"{self.GITHUB_API_BASE}/users/{username}",
                timeout=self.timeout
            )
            
            if response.status_code == 404:
                return {'error': f'User {username} not found'}
            elif response.status_code == 403:
                return {'error': 'Rate limit exceeded or API access forbidden'}
            elif response.status_code != 200:
                return {'error': f'GitHub API error: {response.status_code}'}
            
            data = response.json()
            
            return {
                'username': data.get('login'),
                'id': data.get('id'),
                'name': data.get('name'),
                'bio': data.get('bio'),
                'company': data.get('company'),
                'location': data.get('location'),
                'email': data.get('email'),
                'blog': data.get('blog'),
                'twitter_username': data.get('twitter_username'),
                'public_repos': data.get('public_repos', 0),
                'public_gists': data.get('public_gists', 0),
                'followers': data.get('followers', 0),
                'following': data.get('following', 0),
                'created_at': data.get('created_at'),
                'updated_at': data.get('updated_at'),
                'avatar_url': data.get('avatar_url'),
                'profile_url': data.get('html_url'),
                'type': data.get('type'),  # User or Organization
                'hireable': data.get('hireable')
            }
            
        except Exception as e:
            return {'error': f'Failed to get user info: {str(e)}'}
    
    def get_repository_languages(self, username: str, repo_name: str) -> Dict[str, int]:
        """
        Get programming languages used in a repository.
        
        Args:
            username: Repository owner username
            repo_name: Repository name
            
        Returns:
            Dictionary of languages and their byte counts
        """
        try:
            response = self.session.get(
                f"{self.GITHUB_API_BASE}/repos/{username}/{repo_name}/languages",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {}
                
        except Exception:
            return {}
    
    def get_recent_commits(self, username: str, repo_name: str, days: int = 30) -> Dict[str, Any]:
        """
        Get recent commit activity for a repository.
        
        Args:
            username: Repository owner username
            repo_name: Repository name
            days: Number of days to look back
            
        Returns:
            Recent commit information
        """
        try:
            # Calculate date range
            since_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            response = self.session.get(
                f"{self.GITHUB_API_BASE}/repos/{username}/{repo_name}/commits",
                params={
                    'since': since_date,
                    'per_page': 100  # Get up to 100 recent commits
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                commits = response.json()
                
                # Analyze commit patterns
                commit_analysis = {
                    'total_commits': len(commits),
                    'date_range_days': days,
                    'commits_per_day': round(len(commits) / days, 2) if days > 0 else 0,
                    'contributors': set(),
                    'commit_messages': [],
                    'last_commit_date': None
                }
                
                for commit in commits:
                    # Extract contributor information
                    author = commit.get('commit', {}).get('author', {})
                    if author.get('name'):
                        commit_analysis['contributors'].add(author['name'])
                    
                    # Store commit messages for analysis
                    message = commit.get('commit', {}).get('message', '')
                    if message:
                        commit_analysis['commit_messages'].append(message[:100])  # Truncate long messages
                    
                    # Track last commit date
                    commit_date = commit.get('commit', {}).get('author', {}).get('date')
                    if commit_date and not commit_analysis['last_commit_date']:
                        commit_analysis['last_commit_date'] = commit_date
                
                # Convert set to list for JSON serialization
                commit_analysis['contributors'] = list(commit_analysis['contributors'])
                commit_analysis['unique_contributors'] = len(commit_analysis['contributors'])
                
                return commit_analysis
            else:
                return {'error': f'Failed to get commits: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'Failed to analyze commits: {str(e)}'}
    
    def analyze_repository_security(self, repo_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze repository for potential security concerns.
        
        Args:
            repo_info: Repository information dictionary
            
        Returns:
            Security analysis results
        """
        security_analysis = {
            'risk_level': 'low',
            'concerns': [],
            'recommendations': [],
            'sensitive_indicators': []
        }
        
        repo_name = repo_info.get('name', '').lower()
        description = (repo_info.get('description') or '').lower()
        topics = [topic.lower() for topic in repo_info.get('topics', [])]
        
        # Check for sensitive keywords in repository name and description
        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'api', 'config', 'env',
            'credential', 'auth', 'private', 'internal', 'backup', 'dump',
            'admin', 'exploit', 'vulnerability', 'hack', 'pentest'
        ]
        
        for keyword in sensitive_keywords:
            if keyword in repo_name or keyword in description:
                security_analysis['sensitive_indicators'].append(f"Keyword '{keyword}' found")
                security_analysis['risk_level'] = 'medium'
        
        # Check repository topics for security-related content
        security_topics = ['security', 'pentest', 'exploit', 'vulnerability', 'hacking']
        for topic in topics:
            if topic in security_topics:
                security_analysis['sensitive_indicators'].append(f"Security-related topic: {topic}")
        
        # Check if repository has potentially sensitive files (common patterns)
        if any(pattern in repo_name for pattern in ['.env', 'config', 'secret', 'key']):
            security_analysis['concerns'].append('Repository name suggests configuration or secrets')
            security_analysis['risk_level'] = 'high'
        
        # Check for fork status (forks might contain original sensitive data)
        if repo_info.get('fork'):
            security_analysis['concerns'].append('Repository is a fork - check for exposed secrets from upstream')
        
        # Check for recent activity (abandoned repos might have unpatched vulnerabilities)
        updated_at = repo_info.get('updated_at')
        if updated_at:
            try:
                last_update = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                days_since_update = (datetime.now().replace(tzinfo=last_update.tzinfo) - last_update).days
                
                if days_since_update > 365:
                    security_analysis['concerns'].append(f'Repository not updated for {days_since_update} days')
                    if security_analysis['risk_level'] == 'low':
                        security_analysis['risk_level'] = 'medium'
            except:
                pass
        
        # Generate recommendations
        if security_analysis['risk_level'] == 'high':
            security_analysis['recommendations'].append('Manual review recommended for sensitive content')
        
        if security_analysis['sensitive_indicators']:
            security_analysis['recommendations'].append('Check repository contents for exposed secrets')
        
        if not security_analysis['recommendations']:
            security_analysis['recommendations'].append('Repository appears to have low security risk')
        
        return security_analysis
    
    def get_github_repositories(self, username: str, include_analysis: bool = True) -> Dict[str, Any]:
        """
        Get all public repositories for a GitHub user.
        
        Args:
            username: GitHub username
            include_analysis: Whether to include detailed analysis
            
        Returns:
            Repository information and analysis
        """
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests library not available'}
        
        start_time = time.perf_counter()
        
        # Get user information first
        user_info = self.get_github_user_info(username)
        if user_info.get('error'):
            return {
                'username': username,
                'platform': 'github',
                'error': user_info['error'],
                'duration': round(time.perf_counter() - start_time, 3)
            }
        
        repositories = []
        page = 1
        per_page = 100
        
        try:
            while True:
                response = self.session.get(
                    f"{self.GITHUB_API_BASE}/users/{username}/repos",
                    params={
                        'per_page': per_page,
                        'page': page,
                        'sort': 'updated',
                        'direction': 'desc'
                    },
                    timeout=self.timeout
                )
                
                if response.status_code == 404:
                    return {
                        'username': username,
                        'platform': 'github',
                        'error': f'User {username} not found',
                        'duration': round(time.perf_counter() - start_time, 3)
                    }
                elif response.status_code == 403:
                    return {
                        'username': username,
                        'platform': 'github',
                        'error': 'Rate limit exceeded or API access forbidden',
                        'rate_limit_info': self.check_rate_limit(),
                        'duration': round(time.perf_counter() - start_time, 3)
                    }
                elif response.status_code != 200:
                    return {
                        'username': username,
                        'platform': 'github',
                        'error': f'GitHub API error: {response.status_code}',
                        'duration': round(time.perf_counter() - start_time, 3)
                    }
                
                repos_data = response.json()
                
                # Break if no more repositories
                if not repos_data:
                    break
                
                for repo in repos_data:
                    repo_info = {
                        'name': repo.get('name'),
                        'full_name': repo.get('full_name'),
                        'url': repo.get('html_url'),
                        'clone_url': repo.get('clone_url'),
                        'description': repo.get('description'),
                        'language': repo.get('language'),
                        'stars': repo.get('stargazers_count', 0),
                        'forks': repo.get('forks_count', 0),
                        'watchers': repo.get('watchers_count', 0),
                        'size': repo.get('size', 0),  # Size in KB
                        'open_issues': repo.get('open_issues_count', 0),
                        'topics': repo.get('topics', []),
                        'created_at': repo.get('created_at'),
                        'updated_at': repo.get('updated_at'),
                        'pushed_at': repo.get('pushed_at'),
                        'fork': repo.get('fork', False),
                        'archived': repo.get('archived', False),
                        'disabled': repo.get('disabled', False),
                        'private': repo.get('private', False),
                        'default_branch': repo.get('default_branch'),
                        'license': repo.get('license', {}).get('name') if repo.get('license') else None,
                        'has_issues': repo.get('has_issues', False),
                        'has_wiki': repo.get('has_wiki', False),
                        'has_pages': repo.get('has_pages', False)
                    }
                    
                    # Add detailed analysis if requested
                    if include_analysis:
                        # Get programming languages
                        languages = self.get_repository_languages(username, repo_info['name'])
                        repo_info['languages'] = languages
                        
                        # Calculate language percentages
                        if languages:
                            total_bytes = sum(languages.values())
                            repo_info['language_percentages'] = {
                                lang: round((bytes_count / total_bytes) * 100, 1)
                                for lang, bytes_count in languages.items()
                            }
                        
                        # Get recent commit activity
                        commit_info = self.get_recent_commits(username, repo_info['name'])
                        repo_info['recent_commits'] = commit_info
                        
                        # Perform security analysis
                        security_analysis = self.analyze_repository_security(repo_info)
                        repo_info['security_analysis'] = security_analysis
                    
                    repositories.append(repo_info)
                
                # Check if we got fewer results than requested (last page)
                if len(repos_data) < per_page:
                    break
                
                page += 1
                
                # Add small delay to be respectful to the API
                time.sleep(0.1)
        
        except Exception as e:
            return {
                'username': username,
                'platform': 'github',
                'error': f'Failed to fetch repositories: {str(e)}',
                'duration': round(time.perf_counter() - start_time, 3)
            }
        
        # Sort repositories by stars (most popular first)
        repositories.sort(key=lambda x: x.get('stars', 0), reverse=True)
        
        # Calculate summary statistics
        total_stars = sum(repo.get('stars', 0) for repo in repositories)
        total_forks = sum(repo.get('forks', 0) for repo in repositories)
        languages_used = set()
        security_concerns = 0
        
        for repo in repositories:
            if repo.get('language'):
                languages_used.add(repo['language'])
            
            if repo.get('security_analysis', {}).get('risk_level') in ['medium', 'high']:
                security_concerns += 1
        
        # Get current rate limit status
        rate_limit_info = self.check_rate_limit()
        
        return {
            'username': username,
            'platform': 'github',
            'user_info': user_info,
            'repositories': repositories,
            'summary': {
                'total_repositories': len(repositories),
                'total_stars': total_stars,
                'total_forks': total_forks,
                'languages_used': list(languages_used),
                'unique_languages': len(languages_used),
                'security_concerns': security_concerns,
                'average_stars_per_repo': round(total_stars / len(repositories), 1) if repositories else 0,
                'most_popular_repo': repositories[0] if repositories else None,
                'account_age_days': self._calculate_account_age(user_info.get('created_at'))
            },
            'rate_limit_info': rate_limit_info,
            'duration': round(time.perf_counter() - start_time, 3)
        }
    
    def _calculate_account_age(self, created_at: str) -> Optional[int]:
        """Calculate account age in days."""
        if not created_at:
            return None
        
        try:
            created_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            return (datetime.now().replace(tzinfo=created_date.tzinfo) - created_date).days
        except:
            return None


def run_git_recon(username: str, platform: str = "github") -> Dict[str, Any]:
    """
    Perform comprehensive Git platform reconnaissance.
    
    Args:
        username: Username to investigate
        platform: Platform to use (currently supports 'github')
    
    Returns:
        Dictionary with Git reconnaissance results:
        - "username": target username
        - "platform": platform used for reconnaissance
        - "user_info": detailed user profile information
        - "repositories": list of repository information with analysis
        - "summary": aggregated statistics and insights
        - "rate_limit_info": API rate limit status
        - "duration": analysis duration in seconds
        - "error": error message if reconnaissance failed
        
        Each repository includes:
        - Basic info: name, url, description, stars, forks, language
        - Metadata: topics, creation date, last update, size
        - Language analysis: programming languages and percentages
        - Recent activity: commit analysis and contributor information
        - Security assessment: risk level and potential concerns
    """
    if not username or not username.strip():
        return {
            'username': username,
            'platform': platform,
            'error': 'Username cannot be empty',
            'duration': 0
        }
    
    if not REQUESTS_AVAILABLE:
        return {
            'username': username,
            'platform': platform,
            'error': 'requests library not available. Install with: pip install requests',
            'duration': 0
        }
    
    # Initialize Git reconnaissance engine
    git_recon = GitRecon()
    
    # Currently only GitHub is supported
    if platform.lower() != "github":
        return {
            'username': username,
            'platform': platform,
            'error': f'Platform {platform} not yet supported. Currently supports: github',
            'duration': 0
        }
    
    # Perform GitHub reconnaissance
    result = git_recon.get_github_repositories(username.strip())
    
    return result


def format_git_recon_summary(result: Dict[str, Any]) -> str:
    """
    Format Git reconnaissance results for display.
    
    Args:
        result: Git reconnaissance result dictionary
        
    Returns:
        Formatted string with reconnaissance information
    """
    if result.get('error'):
        return f"Error analyzing {result.get('username', 'unknown')} on {result.get('platform', 'unknown')}: {result['error']}"
    
    lines = []
    username = result.get('username', 'Unknown')
    platform = result.get('platform', 'unknown').title()
    
    lines.append(f"User: {username} ({platform})")
    
    # User information
    user_info = result.get('user_info', {})
    if user_info.get('name'):
        lines.append(f"Name: {user_info['name']}")
    
    if user_info.get('bio'):
        bio = user_info['bio'][:100] + '...' if len(user_info['bio']) > 100 else user_info['bio']
        lines.append(f"Bio: {bio}")
    
    if user_info.get('company'):
        lines.append(f"Company: {user_info['company']}")
    
    if user_info.get('location'):
        lines.append(f"Location: {user_info['location']}")
    
    # Account statistics
    summary = result.get('summary', {})
    lines.append(f"Public Repositories: {summary.get('total_repositories', 0)}")
    lines.append(f"Total Stars: {summary.get('total_stars', 0)}")
    lines.append(f"Total Forks: {summary.get('total_forks', 0)}")
    lines.append(f"Followers: {user_info.get('followers', 0)}")
    lines.append(f"Following: {user_info.get('following', 0)}")
    
    if summary.get('account_age_days'):
        lines.append(f"Account Age: {summary['account_age_days']} days")
    
    # Programming languages
    languages = summary.get('languages_used', [])
    if languages:
        lines.append(f"Languages: {', '.join(languages[:5])}")  # Show first 5
        if len(languages) > 5:
            lines.append(f"  (+{len(languages) - 5} more)")
    
    # Security information
    security_concerns = summary.get('security_concerns', 0)
    if security_concerns > 0:
        lines.append(f"Security Concerns: {security_concerns} repositories flagged")
    
    # Most popular repository
    most_popular = summary.get('most_popular_repo')
    if most_popular:
        stars = most_popular.get('stars', 0)
        lines.append(f"Most Popular: {most_popular.get('name')} ({stars} stars)")
    
    # Rate limit information
    rate_limit = result.get('rate_limit_info', {})
    if rate_limit.get('remaining') is not None:
        lines.append(f"API Requests Remaining: {rate_limit['remaining']}/{rate_limit.get('limit', 'N/A')}")
        if rate_limit.get('authenticated'):
            lines.append("API Status: Authenticated")
    
    lines.append(f"Analysis Duration: {result.get('duration', 0):.3f}s")
    
    return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python git_recon.py <username> [platform]")
        print("Example: python git_recon.py octocat github")
        print("Example: python git_recon.py torvalds")
        print("\nEnvironment variables:")
        print("  GITHUB_TOKEN - GitHub personal access token for higher rate limits")
        sys.exit(1)
    
    username = sys.argv[1]
    platform = sys.argv[2] if len(sys.argv) > 2 else "github"
    
    print(f"Performing Git reconnaissance on: {username} ({platform})")
    print("-" * 80)
    
    result = run_git_recon(username, platform)
    formatted_output = format_git_recon_summary(result)
    
    print(formatted_output)
    
    # Show top repositories if requested
    if '--repos' in sys.argv and not result.get('error'):
        print(f"\nTop Repositories:")
        print("-" * 40)
        repositories = result.get('repositories', [])
        for i, repo in enumerate(repositories[:10], 1):  # Show top 10
            print(f"{i:2d}. {repo.get('name', 'N/A')} ({repo.get('stars', 0)} ⭐)")
            if repo.get('description'):
                desc = repo['description'][:60] + '...' if len(repo['description']) > 60 else repo['description']
                print(f"     {desc}")
            if repo.get('language'):
                print(f"     Language: {repo['language']}")
            print()
    
    # Show security analysis if requested
    if '--security' in sys.argv and not result.get('error'):
        print(f"\nSecurity Analysis:")
        print("-" * 30)
        repositories = result.get('repositories', [])
        for repo in repositories:
            security = repo.get('security_analysis', {})
            if security.get('risk_level') in ['medium', 'high']:
                print(f"⚠️  {repo.get('name')} - {security.get('risk_level').upper()} RISK")
                for concern in security.get('concerns', []):
                    print(f"   - {concern}")
    
    # Also print raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        print(json.dumps(result, indent=2, default=str))
