
import os
import json
import struct
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

try:
    import exifread
    from PIL import Image, ExifTags
    from PIL.ExifTags import TAGS
except ImportError:
    pass

class MetadataAnalyzer:
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        
        return self._full_analysis(file_path)
    
    def analyze_file_for_bot(self, file_path: str) -> Dict[str, Any]:
        full_data = self.analyze_file(file_path)
        return self._clean_for_bot(full_data)
    
    def _full_analysis(self, file_path: str) -> Dict[str, Any]:
        result = {
            "file_info": self._get_file_info(file_path),
            "integrity": {},
            "metadata": {},
            "recovery": {},
            "technical": {},
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        try:
            file_type = self._detect_file_type(file_path)
            result["file_info"]["detected_type"] = file_type
            
            result["integrity"] = self._check_integrity(file_path, file_type)
            
            if file_type.startswith('image/'):
                result["metadata"] = self._extract_image_metadata(file_path)
            elif file_type == 'application/pdf':
                result["metadata"] = self._extract_pdf_metadata(file_path)
            
            result["recovery"] = self._recover_metadata(file_path)
            
            result["technical"] = self._technical_analysis(file_path, file_type)
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        stat = os.stat(file_path)
        return {
            "filename": os.path.basename(file_path),
            "file_path": str(file_path),
            "size_bytes": stat.st_size,
            "size_human": self._bytes_to_human(stat.st_size),
            "creation_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modification_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "access_time": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "file_extension": Path(file_path).suffix.lower(),
            "permissions": oct(stat.st_mode)[-3:],
            "inode": stat.st_ino
        }
    
    def _detect_file_type(self, file_path: str) -> str:
        signatures = {
            b'\xff\xd8\xff': 'image/jpeg',
            b'\x89PNG\r\n\x1a\n': 'image/png',
            b'GIF8': 'image/gif',
            b'BM': 'image/bmp',
            b'II*\x00': 'image/tiff',
            b'MM\x00*': 'image/tiff',
            b'%PDF': 'application/pdf',
            b'PK\x03\x04': 'application/zip',
            b'\xd0\xcf\x11\xe0': 'application/msword',
            b'RIFF': 'video/avi',
        }
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(50)
                for sig, ftype in signatures.items():
                    if header.startswith(sig):
                        return ftype
        except Exception as e:
            return f"unknown/error: {str(e)}"
        
        return "unknown"
    
    def _check_integrity(self, file_path: str, file_type: str) -> Dict[str, Any]:
        integrity = {
            "valid": True,
            "checks_performed": [],
            "issues": [],
            "warnings": []
        }
        
        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                integrity.update({
                    "valid": False,
                    "issues": ["File is empty (0 bytes)"]
                })
                return integrity
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            integrity["checks_performed"].append("file_size_consistent")
            
            if file_type == 'image/jpeg':
                jpeg_checks = self._check_jpeg_integrity(content)
                integrity.update(jpeg_checks)
                
            elif file_type == 'image/png':
                if not content.startswith(b'\x89PNG\r\n\x1a\n'):
                    integrity.update({
                        "valid": False,
                        "issues": ["Invalid PNG signature"]
                    })
            if content.count(b'\x00\x00\x00\x00') > len(content) * 0.1:
                integrity["warnings"].append("High number of null bytes - possible data corruption")
                
        except Exception as e:
            integrity.update({
                "valid": False,
                "issues": [f"Integrity check error: {str(e)}"]
            })
        
        return integrity
    
    def _check_jpeg_integrity(self, content: bytes) -> Dict[str, Any]:
        result = {
            "valid": True,
            "jpeg_structure": {},
            "issues": []
        }
        
        if not content.startswith(b'\xff\xd8\xff'):
            result["issues"].append("Invalid JPEG start marker")
            result["valid"] = False
        
        if not content.endswith(b'\xff\xd9'):
            result["issues"].append("Missing JPEG end marker (FFD9)")
            result["valid"] = False
        
        try:
            segments = []
            pos = 0
            
            while pos < len(content) - 1:
                if content[pos] == 0xFF:
                    marker = content[pos + 1]
                    marker_name = self._get_jpeg_marker_name(marker)
                    
                    segment_info = {
                        "position": pos,
                        "marker": f"0x{marker:02x}",
                        "name": marker_name
                    }
                    
                    if marker in [0xC0, 0xC2, 0xC4, 0xDB, 0xE0, 0xE1, 0xE2, 0xED, 0xFE]:
                        if pos + 3 < len(content):
                            length = struct.unpack('>H', content[pos+2:pos+4])[0]
                            segment_info["length"] = length
                            pos += length + 2
                        else:
                            result["issues"].append(f"Truncated segment at position {pos}")
                            break
                    else:
                        pos += 2
                    
                    segments.append(segment_info)
                    
                    if marker == 0xD9:
                        break
                else:
                    result["issues"].append(f"Invalid JPEG data at position {pos}")
                    break
            
            result["jpeg_structure"] = {
                "segments_found": len(segments),
                "segments": segments[:10]  
            }
            
        except Exception as e:
            result["issues"].append(f"Structure analysis error: {str(e)}")
        
        return result
    
    def _get_jpeg_marker_name(self, marker: int) -> str:
        markers = {
            0xD8: "SOI", 0xC0: "SOF0", 0xC2: "SOF2", 0xC4: "DHT", 
            0xDB: "DQT", 0xDD: "DRI", 0xDA: "SOS", 0xD9: "EOI",
            0xFE: "COM", 0xE0: "APP0", 0xE1: "APP1", 0xE2: "APP2",
            0xED: "APP13", 0xEE: "APP14"
        }
        return markers.get(marker, f"Unknown(0x{marker:02x})")
    
    def _extract_image_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata = {"type": "image"}
        
        try:
            with open(file_path, 'rb') as f:
                tags = exifread.process_file(f, details=False)
            
            if tags:
                metadata["exif"] = {}
                categories = {
                    'camera_info': ['Image Make', 'Image Model', 'Image Software'],
                    'date_time': ['Image DateTime', 'EXIF DateTimeOriginal', 'EXIF DateTimeDigitized'],
                    'gps_data': ['GPS GPSLatitude', 'GPS GPSLongitude', 'GPS GPSAltitude'],
                    'camera_settings': ['EXIF ExposureTime', 'EXIF FNumber', 'EXIF ISOSpeedRatings', 
                                      'EXIF FocalLength', 'EXIF Flash', 'EXIF WhiteBalance'],
                    'image_properties': ['EXIF ExifImageWidth', 'EXIF ExifImageLength', 'Image Orientation'],
                    'other': []
                }
                
                for tag, value in tags.items():
                    tag_str = str(tag)
                    if tag_str in ['JPEGThumbnail', 'TIFFThumbnail', 'Filename']:
                        continue
                    
                    found_category = 'other'
                    for category, patterns in categories.items():
                        if any(pattern in tag_str for pattern in patterns):
                            found_category = category
                            break
                    
                    if found_category not in metadata["exif"]:
                        metadata["exif"][found_category] = {}
                    
                    metadata["exif"][found_category][tag_str] = str(value)
        except Exception as e:
            metadata["exif_error"] = str(e)
        
        try:
            with Image.open(file_path) as img:
                metadata["image_info"] = {
                    "format": img.format,
                    "dimensions": f"{img.width}x{img.height}",
                    "mode": img.mode,
                    "color_palette": getattr(img, 'palette', 'None'),
                    "info": dict(img.info) if hasattr(img, 'info') else {}
                }
                
                try:
                    exif_data = img._getexif()
                    if exif_data:
                        pil_exif = {}
                        for tag_id, value in exif_data.items():
                            tag_name = TAGS.get(tag_id, tag_id)
                            pil_exif[str(tag_name)] = str(value)
                        metadata["pil_exif"] = pil_exif
                except:
                    pass
                    
        except Exception as e:
            metadata["pil_error"] = str(e)
        
        return metadata
    
    def _extract_pdf_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata = {"type": "pdf"}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read().decode('latin-1', errors='ignore')
            
            fields = {
                'title': '/Title', 'author': '/Author', 'subject': '/Subject',
                'keywords': '/Keywords', 'creator': '/Creator', 'producer': '/Producer',
                'creation_date': '/CreationDate', 'mod_date': '/ModDate'
            }
            
            pdf_info = {}
            for key, pattern in fields.items():
                if pattern in content:
                    start = content.find(pattern) + len(pattern)
                    end = min(content.find('>>', start), content.find('/', start), content.find('\n', start))
                    if end != -1:
                        value = content[start:end].strip()
                        if value.startswith('('):
                            value = value[1:-1]
                        pdf_info[key] = value
            
            if pdf_info:
                metadata["pdf_info"] = pdf_info
            
            metadata["pdf_stats"] = {
                "estimated_pages": content.count('/Type/Page'),
                "has_javascript": '/JavaScript' in content,
                "has_forms": '/AcroForm' in content,
                "has_attachments": '/EmbeddedFile' in content,
                "is_linearized": 'Linearized' in content[:1000]
            }
            
        except Exception as e:
            metadata["pdf_error"] = str(e)
        
        return metadata
    
    def _recover_metadata(self, file_path: str) -> Dict[str, Any]:
        recovery = {"found_data": {}}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            signatures = {
                'exif': b'Exif',
                'xmp': b'http://ns.adobe.com/xap',
                'iptc': b'\x1c\x02',
                'gps': b'GPS',
                'icc_profile': b'ICC_PROFILE',
                'photoshop': b'Photoshop',
                'comment': b'\xff\xfe',
                'maker_note': b'MakerNote'
            }
            
            found_signatures = []
            for name, sig in signatures.items():
                pos = content.find(sig)
                if pos != -1:
                    found_signatures.append({
                        "type": name,
                        "position": pos
                    })
            
            if found_signatures:
                recovery["found_data"]["signatures"] = found_signatures
            
            strings = []
            current_string = ""
            for byte in content[:10000]:  
                if 32 <= byte < 127:
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 6:
                        strings.append(current_string)
                    current_string = ""
            
            if len(current_string) >= 6:
                strings.append(current_string)
            
            if strings:
                recovery["found_data"]["embedded_strings"] = strings[:10]
            
        except Exception as e:
            recovery["error"] = str(e)
        
        return recovery
    
    def _technical_analysis(self, file_path: str, file_type: str) -> Dict[str, Any]:
        technical = {}
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)
                technical["header_analysis"] = {
                    "size": len(header),
                    "magic_bytes": header[:8].hex()
                }
                
                strings = []
                current = ""
                for byte in header:
                    if 32 <= byte < 127:
                        current += chr(byte)
                    else:
                        if len(current) >= 4:
                            strings.append(current)
                        current = ""
                
                if strings:
                    technical["header_strings"] = strings
            
        except Exception as e:
            technical["error"] = str(e)
        
        return technical
    
    def _bytes_to_human(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def _clean_for_bot(self, full_result: Dict[str, Any]) -> Dict[str, Any]:
        if "error" in full_result:
            return full_result
        
        cleaned = {}
        
        if "file_info" in full_result:
            file_info = full_result["file_info"]
            cleaned["file"] = {
                "name": file_info.get("filename"),
                "size": file_info.get("size_bytes"),
                "modified": file_info.get("modification_time"),
                "type": file_info.get("detected_type")
            }
        
        if "integrity" in full_result:
            integrity = full_result["integrity"]
            if not integrity.get("valid", True) or integrity.get("issues"):
                cleaned["integrity"] = {
                    "valid": integrity.get("valid"),
                    "issues": integrity.get("issues", [])[:3]  
                }
        
        if "metadata" in full_result:
            metadata = full_result["metadata"]
            cleaned_metadata = {}
            
            if "exif" in metadata:
                cleaned_metadata["exif"] = metadata["exif"]
            
            if "image_info" in metadata:
                image_info = metadata["image_info"]
                cleaned_metadata["image"] = {
                    "format": image_info.get("format"),
                    "width": image_info.get("dimensions", "").split('x')[0] if 'x' in image_info.get("dimensions", "") else "",
                    "height": image_info.get("dimensions", "").split('x')[1] if 'x' in image_info.get("dimensions", "") else ""
                }
            
            if cleaned_metadata:
                cleaned["metadata"] = cleaned_metadata
        
        if "recovery" in full_result:
            recovery = full_result["recovery"]
            if recovery.get("found_data", {}).get("signatures"):
                cleaned["recovered"] = {
                    "signatures_found": len(recovery["found_data"]["signatures"])
                }
        
        cleaned["analyzed_at"] = full_result.get("analysis_timestamp")
        
        return self._remove_empty_fields(cleaned)
    
    def _remove_empty_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(data, dict):
            return {k: self._remove_empty_fields(v) for k, v in data.items() 
                   if v not in [None, "", {}, []] and self._remove_empty_fields(v) not in [None, "", {}, []]}
        elif isinstance(data, list):
            return [self._remove_empty_fields(item) for item in data if item not in [None, "", {}, []]]
        else:
            return data

def analyze_file(file_path: str) -> Dict[str, Any]:
    analyzer = MetadataAnalyzer()
    return analyzer.analyze_file(file_path)

def analyze_file_for_bot(file_path: str) -> Dict[str, Any]:
    analyzer = MetadataAnalyzer()
    return analyzer.analyze_file_for_bot(file_path)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print('Usage: python metadata_analyzer.py <file_path>')
        sys.exit(1)
    result = analyze_file(sys.argv[1])
    print(json.dumps(result, indent=2, ensure_ascii=False))