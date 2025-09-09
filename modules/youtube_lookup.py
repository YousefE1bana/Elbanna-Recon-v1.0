#!/usr/bin/env python3
"""
YouTube Lookup Module for Elbanna Recon v1.0

This module provides comprehensive YouTube video and channel metadata extraction.
Features:
- Video metadata extraction via YouTube oEmbed API
- Channel information gathering with fallback methods
- Video statistics and engagement analysis
- Channel subscriber and video count estimation
- Thumbnail quality analysis and extraction
- Video duration and upload date parsing
- Comment and engagement metrics (when available)

Author: Yousef Osama
"""

import time
import re
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, parse_qs
import json

# Try to import requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class YouTubeLookup:
    """
    YouTube video and channel metadata extraction engine.
    """
    
    # User agent for requests
    USER_AGENT = "Elbanna-Recon-v1.0-YouTubeLookup"
    
    # Request timeout settings
    DEFAULT_TIMEOUT = 15
    
    # YouTube oEmbed endpoint
    OEMBED_ENDPOINT = "https://www.youtube.com/oembed"
    
    # YouTube URL patterns
    VIDEO_URL_PATTERNS = [
        r'(?:youtube\.com/watch\?v=|youtu\.be/|youtube\.com/embed/)([a-zA-Z0-9_-]{11})',
        r'youtube\.com/v/([a-zA-Z0-9_-]{11})',
        r'youtube\.com/watch\?.*v=([a-zA-Z0-9_-]{11})'
    ]
    
    CHANNEL_URL_PATTERNS = [
        r'youtube\.com/channel/([a-zA-Z0-9_-]+)',
        r'youtube\.com/user/([a-zA-Z0-9_-]+)',
        r'youtube\.com/c/([a-zA-Z0-9_-]+)',
        r'youtube\.com/@([a-zA-Z0-9_.-]+)'
    ]
    
    # Thumbnail quality levels
    THUMBNAIL_QUALITIES = {
        'maxresdefault': 'Maximum Resolution (1280x720)',
        'sddefault': 'Standard Definition (640x480)',
        'hqdefault': 'High Quality (480x360)',
        'mqdefault': 'Medium Quality (320x180)',
        'default': 'Default (120x90)'
    }
    
    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        """
        Initialize the YouTube lookup engine.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = None
        
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': self.USER_AGENT,
                'Accept': 'application/json, text/html, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br'
            })
    
    def extract_video_id(self, url: str) -> Optional[str]:
        """
        Extract YouTube video ID from various URL formats.
        
        Args:
            url: YouTube video URL
            
        Returns:
            Video ID or None if not found
        """
        for pattern in self.VIDEO_URL_PATTERNS:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None
    
    def extract_channel_info(self, url: str) -> Dict[str, Optional[str]]:
        """
        Extract channel information from YouTube URL.
        
        Args:
            url: YouTube channel URL
            
        Returns:
            Dictionary with channel type and identifier
        """
        channel_info = {
            'type': None,
            'identifier': None,
            'url_type': 'unknown'
        }
        
        for pattern in self.CHANNEL_URL_PATTERNS:
            match = re.search(pattern, url)
            if match:
                channel_info['identifier'] = match.group(1)
                
                if 'channel/' in pattern:
                    channel_info['type'] = 'channel_id'
                    channel_info['url_type'] = 'channel'
                elif 'user/' in pattern:
                    channel_info['type'] = 'username'
                    channel_info['url_type'] = 'user'
                elif '/c/' in pattern:
                    channel_info['type'] = 'custom_name'
                    channel_info['url_type'] = 'custom'
                elif '@' in pattern:
                    channel_info['type'] = 'handle'
                    channel_info['url_type'] = 'handle'
                
                break
        
        return channel_info
    
    def is_video_url(self, url: str) -> bool:
        """Check if URL is a YouTube video URL."""
        return self.extract_video_id(url) is not None
    
    def is_channel_url(self, url: str) -> bool:
        """Check if URL is a YouTube channel URL."""
        channel_info = self.extract_channel_info(url)
        return channel_info['identifier'] is not None
    
    def get_oembed_data(self, video_url: str) -> Dict[str, Any]:
        """
        Get video metadata using YouTube oEmbed API.
        
        Args:
            video_url: YouTube video URL
            
        Returns:
            oEmbed response data
        """
        start_time = time.perf_counter()
        
        try:
            params = {
                'url': video_url,
                'format': 'json'
            }
            
            response = self.session.get(
                self.OEMBED_ENDPOINT,
                params=params,
                timeout=self.timeout
            )
            
            response_time = time.perf_counter() - start_time
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'data': data,
                    'response_time': round(response_time * 1000, 2)
                }
            elif response.status_code == 401:
                return {
                    'success': False,
                    'error': 'Unauthorized - Video may be private or restricted',
                    'response_time': round(response_time * 1000, 2)
                }
            elif response.status_code == 404:
                return {
                    'success': False,
                    'error': 'Video not found or URL is invalid',
                    'response_time': round(response_time * 1000, 2)
                }
            else:
                return {
                    'success': False,
                    'error': f'HTTP {response.status_code}: {response.reason}',
                    'response_time': round(response_time * 1000, 2)
                }
                
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': f'Request timed out after {self.timeout} seconds',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Request error: {str(e)}',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
        except json.JSONDecodeError:
            return {
                'success': False,
                'error': 'Invalid JSON response from YouTube',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'response_time': round((time.perf_counter() - start_time) * 1000, 2)
            }
    
    def get_thumbnail_variants(self, video_id: str) -> Dict[str, str]:
        """
        Generate thumbnail URLs for different quality levels.
        
        Args:
            video_id: YouTube video ID
            
        Returns:
            Dictionary of thumbnail URLs by quality
        """
        base_url = f"https://img.youtube.com/vi/{video_id}"
        
        thumbnails = {}
        for quality, description in self.THUMBNAIL_QUALITIES.items():
            thumbnails[quality] = {
                'url': f"{base_url}/{quality}.jpg",
                'description': description
            }
        
        return thumbnails
    
    def extract_additional_metadata(self, video_url: str, video_id: str) -> Dict[str, Any]:
        """
        Extract additional metadata by parsing the video page.
        
        Args:
            video_url: YouTube video URL
            video_id: YouTube video ID
            
        Returns:
            Additional metadata information
        """
        additional_data = {
            'view_count': None,
            'like_count': None,
            'upload_date': None,
            'duration': None,
            'description_snippet': None,
            'tags': [],
            'category': None
        }
        
        try:
            # Attempt to get basic page data
            response = self.session.get(video_url, timeout=self.timeout)
            
            if response.status_code == 200:
                content = response.text
                
                # Extract view count
                view_match = re.search(r'"viewCount":"(\d+)"', content)
                if view_match:
                    additional_data['view_count'] = int(view_match.group(1))
                
                # Extract upload date
                date_match = re.search(r'"uploadDate":"([^"]+)"', content)
                if date_match:
                    additional_data['upload_date'] = date_match.group(1)
                
                # Extract duration
                duration_match = re.search(r'"lengthSeconds":"(\d+)"', content)
                if duration_match:
                    duration_seconds = int(duration_match.group(1))
                    additional_data['duration'] = self._format_duration(duration_seconds)
                
                # Extract description snippet
                desc_match = re.search(r'"shortDescription":"([^"]{0,200})', content)
                if desc_match:
                    additional_data['description_snippet'] = desc_match.group(1)[:200]
                
        except Exception:
            # If scraping fails, continue with oEmbed data only
            pass
        
        return additional_data
    
    def _format_duration(self, seconds: int) -> str:
        """
        Format duration from seconds to human-readable format.
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            Formatted duration string
        """
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        
        if hours > 0:
            return f"{hours}:{minutes:02d}:{secs:02d}"
        else:
            return f"{minutes}:{secs:02d}"
    
    def scrape_channel_basic_info(self, channel_url: str) -> Dict[str, Any]:
        """
        Attempt to scrape basic channel information.
        
        Args:
            channel_url: YouTube channel URL
            
        Returns:
            Basic channel information
        """
        channel_data = {
            'success': False,
            'channel_name': None,
            'subscriber_count': None,
            'video_count': None,
            'description': None,
            'avatar_url': None,
            'banner_url': None,
            'verified': False,
            'join_date': None
        }
        
        try:
            response = self.session.get(channel_url, timeout=self.timeout)
            
            if response.status_code == 200:
                content = response.text
                
                # Extract channel name
                name_patterns = [
                    r'"channelMetadataRenderer".*?"title":"([^"]+)"',
                    r'<meta property="og:title" content="([^"]+)"',
                    r'"header".*?"channelName":"([^"]+)"'
                ]
                
                for pattern in name_patterns:
                    match = re.search(pattern, content)
                    if match:
                        channel_data['channel_name'] = match.group(1)
                        break
                
                # Extract subscriber count
                sub_patterns = [
                    r'"subscriberCountText".*?"runs".*?"text":"([^"]+)"',
                    r'"subscriberCountText".*?"simpleText":"([^"]+)"'
                ]
                
                for pattern in sub_patterns:
                    match = re.search(pattern, content)
                    if match:
                        channel_data['subscriber_count'] = match.group(1)
                        break
                
                # Extract description
                desc_match = re.search(r'"description":"([^"]{0,500})', content)
                if desc_match:
                    channel_data['description'] = desc_match.group(1)[:500]
                
                # Check if verified
                if '"badges"' in content and 'VERIFIED' in content:
                    channel_data['verified'] = True
                
                channel_data['success'] = True
                
        except Exception as e:
            channel_data['error'] = f'Scraping failed: {str(e)}'
        
        return channel_data
    
    def lookup_video(self, video_url: str) -> Dict[str, Any]:
        """
        Comprehensive video metadata lookup.
        
        Args:
            video_url: YouTube video URL
            
        Returns:
            Complete video information
        """
        start_time = time.perf_counter()
        
        # Extract video ID
        video_id = self.extract_video_id(video_url)
        if not video_id:
            return {
                'success': False,
                'error': 'Invalid YouTube video URL format',
                'url': video_url,
                'duration': 0
            }
        
        result = {
            'success': False,
            'url': video_url,
            'video_id': video_id,
            'oembed_data': {},
            'additional_metadata': {},
            'thumbnails': {},
            'analysis': {}
        }
        
        # Get oEmbed data
        oembed_result = self.get_oembed_data(video_url)
        result['oembed_data'] = oembed_result
        
        if oembed_result.get('success'):
            oembed_data = oembed_result.get('data', {})
            
            # Extract core information
            result.update({
                'success': True,
                'title': oembed_data.get('title'),
                'author_name': oembed_data.get('author_name'),
                'author_url': oembed_data.get('author_url'),
                'provider_name': oembed_data.get('provider_name', 'YouTube'),
                'provider_url': oembed_data.get('provider_url', 'https://www.youtube.com/'),
                'thumbnail_url': oembed_data.get('thumbnail_url'),
                'thumbnail_width': oembed_data.get('thumbnail_width'),
                'thumbnail_height': oembed_data.get('thumbnail_height'),
                'width': oembed_data.get('width'),
                'height': oembed_data.get('height'),
                'html': oembed_data.get('html')
            })
            
            # Get thumbnail variants
            result['thumbnails'] = self.get_thumbnail_variants(video_id)
            
            # Extract additional metadata
            result['additional_metadata'] = self.extract_additional_metadata(video_url, video_id)
            
            # Analysis
            result['analysis'] = {
                'video_quality': self._analyze_video_quality(oembed_data),
                'channel_info': self._analyze_channel_info(oembed_data),
                'embed_restrictions': self._check_embed_restrictions(oembed_data),
                'content_type': self._classify_content_type(oembed_data.get('title', ''))
            }
        
        result['duration'] = round(time.perf_counter() - start_time, 3)
        
        return result
    
    def lookup_channel(self, channel_url: str) -> Dict[str, Any]:
        """
        Channel information lookup.
        
        Args:
            channel_url: YouTube channel URL
            
        Returns:
            Channel information and analysis
        """
        start_time = time.perf_counter()
        
        # Extract channel information
        channel_info = self.extract_channel_info(channel_url)
        
        if not channel_info['identifier']:
            return {
                'success': False,
                'error': 'Invalid YouTube channel URL format',
                'url': channel_url,
                'duration': round(time.perf_counter() - start_time, 3)
            }
        
        result = {
            'success': False,
            'url': channel_url,
            'channel_info': channel_info,
            'scraped_data': {},
            'analysis': {},
            'api_note': 'Full channel analytics require YouTube Data API v3 key'
        }
        
        # Attempt basic scraping
        scraped_data = self.scrape_channel_basic_info(channel_url)
        result['scraped_data'] = scraped_data
        
        if scraped_data.get('success'):
            result['success'] = True
            result.update({
                'channel_name': scraped_data.get('channel_name'),
                'subscriber_count': scraped_data.get('subscriber_count'),
                'description': scraped_data.get('description'),
                'verified': scraped_data.get('verified', False)
            })
            
            # Analysis
            result['analysis'] = {
                'channel_size': self._analyze_channel_size(scraped_data.get('subscriber_count')),
                'verification_status': scraped_data.get('verified', False),
                'content_focus': self._analyze_channel_content(scraped_data.get('description', '')),
                'engagement_potential': self._estimate_engagement_potential(scraped_data)
            }
        
        result['duration'] = round(time.perf_counter() - start_time, 3)
        
        return result
    
    def _analyze_video_quality(self, oembed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze video quality based on oEmbed data."""
        width = oembed_data.get('width', 0)
        height = oembed_data.get('height', 0)
        
        if height >= 1080:
            quality = 'Full HD (1080p+)'
        elif height >= 720:
            quality = 'HD (720p)'
        elif height >= 480:
            quality = 'SD (480p)'
        else:
            quality = 'Low Quality'
        
        return {
            'resolution': f"{width}x{height}" if width and height else 'Unknown',
            'quality_rating': quality,
            'aspect_ratio': round(width / height, 2) if width and height else None
        }
    
    def _analyze_channel_info(self, oembed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze channel information from oEmbed data."""
        author_name = oembed_data.get('author_name', '')
        author_url = oembed_data.get('author_url', '')
        
        return {
            'channel_name': author_name,
            'channel_url': author_url,
            'is_verified': 'VERIFIED' in author_name.upper() or '✓' in author_name,
            'channel_type': self._classify_channel_type(author_name)
        }
    
    def _check_embed_restrictions(self, oembed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check for embedding restrictions."""
        html = oembed_data.get('html', '')
        
        return {
            'embeddable': bool(html),
            'embed_html_available': bool(html),
            'iframe_present': '<iframe' in html if html else False
        }
    
    def _classify_content_type(self, title: str) -> str:
        """Classify video content type based on title."""
        title_lower = title.lower()
        
        if any(word in title_lower for word in ['tutorial', 'how to', 'guide', 'lesson']):
            return 'Educational'
        elif any(word in title_lower for word in ['music', 'song', 'album', 'audio']):
            return 'Music'
        elif any(word in title_lower for word in ['news', 'breaking', 'update', 'report']):
            return 'News'
        elif any(word in title_lower for word in ['game', 'gaming', 'gameplay', 'playthrough']):
            return 'Gaming'
        elif any(word in title_lower for word in ['review', 'unboxing', 'test']):
            return 'Review'
        elif any(word in title_lower for word in ['vlog', 'daily', 'lifestyle']):
            return 'Vlog'
        else:
            return 'General'
    
    def _analyze_channel_size(self, subscriber_count: Optional[str]) -> str:
        """Analyze channel size based on subscriber count."""
        if not subscriber_count:
            return 'Unknown'
        
        # Extract numbers from subscriber count string
        numbers = re.findall(r'[\d.]+', subscriber_count)
        if not numbers:
            return 'Unknown'
        
        try:
            count_str = numbers[0]
            if 'K' in subscriber_count.upper():
                count = float(count_str) * 1000
            elif 'M' in subscriber_count.upper():
                count = float(count_str) * 1000000
            else:
                count = float(count_str)
            
            if count >= 10000000:
                return 'Mega Channel (10M+)'
            elif count >= 1000000:
                return 'Large Channel (1M+)'
            elif count >= 100000:
                return 'Medium Channel (100K+)'
            elif count >= 10000:
                return 'Growing Channel (10K+)'
            elif count >= 1000:
                return 'Small Channel (1K+)'
            else:
                return 'New Channel (<1K)'
        except:
            return 'Unknown'
    
    def _classify_channel_type(self, channel_name: str) -> str:
        """Classify channel type based on name patterns."""
        name_lower = channel_name.lower()
        
        if any(word in name_lower for word in ['official', 'vevo', 'records']):
            return 'Official/Label'
        elif any(word in name_lower for word in ['tv', 'news', 'network', 'media']):
            return 'Media/News'
        elif any(word in name_lower for word in ['gaming', 'gamer', 'plays']):
            return 'Gaming'
        elif any(word in name_lower for word in ['tech', 'review', 'unbox']):
            return 'Technology'
        else:
            return 'Personal/Creator'
    
    def _analyze_channel_content(self, description: str) -> str:
        """Analyze channel content focus from description."""
        if not description:
            return 'Unknown'
        
        desc_lower = description.lower()
        
        if any(word in desc_lower for word in ['music', 'song', 'artist', 'album']):
            return 'Music'
        elif any(word in desc_lower for word in ['tech', 'technology', 'gadget', 'review']):
            return 'Technology'
        elif any(word in desc_lower for word in ['game', 'gaming', 'esports']):
            return 'Gaming'
        elif any(word in desc_lower for word in ['education', 'learn', 'tutorial', 'course']):
            return 'Education'
        elif any(word in desc_lower for word in ['news', 'politics', 'current']):
            return 'News/Politics'
        elif any(word in desc_lower for word in ['comedy', 'funny', 'humor']):
            return 'Comedy'
        else:
            return 'General/Lifestyle'
    
    def _estimate_engagement_potential(self, scraped_data: Dict[str, Any]) -> str:
        """Estimate engagement potential based on available data."""
        is_verified = scraped_data.get('verified', False)
        has_description = bool(scraped_data.get('description'))
        subscriber_count = scraped_data.get('subscriber_count', '')
        
        score = 0
        
        if is_verified:
            score += 3
        if has_description:
            score += 2
        if any(size in subscriber_count.upper() for size in ['K', 'M']):
            score += 2
        
        if score >= 5:
            return 'High'
        elif score >= 3:
            return 'Medium'
        else:
            return 'Low'


def run_youtube_lookup(video_or_channel_url: str) -> Dict[str, Any]:
    """
    Lookup YouTube video or channel metadata.
    
    Args:
        video_or_channel_url: YouTube video or channel URL
    
    Returns:
        Dictionary with YouTube metadata:
        
        For videos:
        - "success": boolean indicating if lookup was successful
        - "title": video title
        - "author_name": channel name
        - "author_url": channel URL
        - "provider_name": "YouTube"
        - "thumbnail_url": video thumbnail URL
        - "video_id": extracted video ID
        - "thumbnails": various quality thumbnail URLs
        - "additional_metadata": view count, duration, upload date (if available)
        - "analysis": video quality, content type, channel info
        - "duration": lookup duration in seconds
        - "error": error message if lookup failed
        
        For channels:
        - "success": boolean indicating if lookup was successful
        - "channel_name": channel display name
        - "subscriber_count": subscriber count string
        - "description": channel description
        - "verified": boolean indicating verification status
        - "channel_info": URL type and identifier
        - "analysis": channel size, content focus, engagement potential
        - "api_note": information about API requirements for full data
        - "duration": lookup duration in seconds
        - "error": error message if lookup failed
    """
    if not video_or_channel_url or not video_or_channel_url.strip():
        return {
            'error': 'YouTube URL cannot be empty',
            'duration': 0
        }
    
    if not REQUESTS_AVAILABLE:
        return {
            'error': 'requests library not available. Install with: pip install requests',
            'duration': 0
        }
    
    url = video_or_channel_url.strip()
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Check if it's a valid YouTube URL
    if 'youtube.com' not in url and 'youtu.be' not in url:
        return {
            'error': 'URL must be a valid YouTube URL (youtube.com or youtu.be)',
            'url': url,
            'duration': 0
        }
    
    # Initialize YouTube lookup
    youtube = YouTubeLookup()
    
    # Determine if it's a video or channel URL
    if youtube.is_video_url(url):
        return youtube.lookup_video(url)
    elif youtube.is_channel_url(url):
        return youtube.lookup_channel(url)
    else:
        return {
            'error': 'URL format not recognized. Please provide a valid YouTube video or channel URL.',
            'url': url,
            'supported_formats': [
                'Video: youtube.com/watch?v=VIDEO_ID',
                'Video: youtu.be/VIDEO_ID', 
                'Channel: youtube.com/channel/CHANNEL_ID',
                'Channel: youtube.com/user/USERNAME',
                'Channel: youtube.com/c/CUSTOM_NAME',
                'Channel: youtube.com/@HANDLE'
            ],
            'duration': 0
        }


def format_youtube_summary(result: Dict[str, Any]) -> str:
    """
    Format YouTube lookup results for display.
    
    Args:
        result: YouTube lookup result dictionary
        
    Returns:
        Formatted string with YouTube information
    """
    if result.get('error'):
        return f"Error looking up YouTube content: {result['error']}"
    
    lines = []
    
    if result.get('title'):  # Video result
        lines.append(f"Title: {result.get('title', 'Unknown')}")
        lines.append(f"Channel: {result.get('author_name', 'Unknown')}")
        if result.get('author_url'):
            lines.append(f"Channel URL: {result.get('author_url')}")
        
        # Additional metadata
        additional = result.get('additional_metadata', {})
        if additional.get('view_count'):
            lines.append(f"View Count: {additional['view_count']:,}")
        if additional.get('duration'):
            lines.append(f"Duration: {additional['duration']}")
        if additional.get('upload_date'):
            lines.append(f"Upload Date: {additional['upload_date']}")
        
        # Analysis
        analysis = result.get('analysis', {})
        video_quality = analysis.get('video_quality', {})
        if video_quality.get('quality_rating'):
            lines.append(f"Quality: {video_quality['quality_rating']}")
        
        content_type = analysis.get('content_type')
        if content_type:
            lines.append(f"Content Type: {content_type}")
        
        # Thumbnail info
        if result.get('thumbnail_url'):
            lines.append(f"Thumbnail: {result['thumbnail_url']}")
        
    elif result.get('channel_name'):  # Channel result
        lines.append(f"Channel Name: {result.get('channel_name', 'Unknown')}")
        
        if result.get('subscriber_count'):
            lines.append(f"Subscribers: {result['subscriber_count']}")
        
        if result.get('verified'):
            lines.append("Status: Verified ✓")
        
        if result.get('description'):
            desc = result['description'][:100]
            if len(result['description']) > 100:
                desc += "..."
            lines.append(f"Description: {desc}")
        
        # Analysis
        analysis = result.get('analysis', {})
        if analysis.get('channel_size'):
            lines.append(f"Channel Size: {analysis['channel_size']}")
        if analysis.get('content_focus'):
            lines.append(f"Content Focus: {analysis['content_focus']}")
        if analysis.get('engagement_potential'):
            lines.append(f"Engagement Potential: {analysis['engagement_potential']}")
        
        # API note
        if result.get('api_note'):
            lines.append(f"Note: {result['api_note']}")
    
    lines.append(f"Lookup Duration: {result.get('duration', 0):.3f}s")
    
    return '\n'.join(lines)


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python youtube_lookup.py <youtube_url>")
        print("Example: python youtube_lookup.py https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        print("Example: python youtube_lookup.py https://www.youtube.com/channel/UCuAXFkgsw1L7xaCfnd5JJOw")
        print("Example: python youtube_lookup.py https://www.youtube.com/@YouTube")
        sys.exit(1)
    
    url = sys.argv[1]
    
    print(f"Looking up YouTube content: {url}")
    print("-" * 80)
    
    result = run_youtube_lookup(url)
    formatted_output = format_youtube_summary(result)
    
    print(formatted_output)
    
    # Show additional details if requested
    if '--detailed' in sys.argv and not result.get('error'):
        print(f"\nDetailed Information:")
        print("-" * 40)
        
        if result.get('video_id'):  # Video
            print(f"Video ID: {result['video_id']}")
            
            thumbnails = result.get('thumbnails', {})
            if thumbnails:
                print("Available Thumbnails:")
                for quality, info in thumbnails.items():
                    print(f"  {quality}: {info['url']}")
            
            oembed_data = result.get('oembed_data', {})
            if oembed_data.get('success'):
                response_time = oembed_data.get('response_time', 0)
                print(f"oEmbed Response Time: {response_time}ms")
        
        elif result.get('channel_info'):  # Channel
            channel_info = result['channel_info']
            print(f"Channel Type: {channel_info.get('type')}")
            print(f"Channel Identifier: {channel_info.get('identifier')}")
            print(f"URL Type: {channel_info.get('url_type')}")
    
    # Also print raw result for debugging
    if '--debug' in sys.argv:
        print("\nRaw result:")
        import json
        print(json.dumps(result, indent=2, default=str))
