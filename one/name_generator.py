"""随机名字生成器"""
import random


# 真实常见姓名池：SheerID 风控会判「信息是否正确」，
# 拼接出来的姓（Parianworth / Fredwick 这种）没有现实分布，属于明显合成身份。
REAL_FIRST_NAMES = [
    "Michael", "Christopher", "Daniel", "Matthew", "Joshua", "Andrew", "James",
    "Ryan", "Nicholas", "Tyler", "Jacob", "Brandon", "Justin", "Kevin", "Eric",
    "Emily", "Sarah", "Jessica", "Ashley", "Amanda", "Megan", "Rachel", "Lauren",
    "Hannah", "Olivia", "Sophia", "Emma", "Chloe", "Grace", "Natalie", "Katherine",
]

REAL_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Miller", "Davis", "Garcia",
    "Rodriguez", "Wilson", "Martinez", "Anderson", "Taylor", "Thomas", "Moore",
    "Jackson", "Martin", "Lee", "Thompson", "White", "Harris", "Clark", "Lewis",
    "Robinson", "Walker", "Young", "Allen", "King", "Wright", "Scott", "Nguyen",
    "Patel", "Kim", "Chen", "Rivera", "Cooper", "Morgan", "Bailey", "Reed",
]


class NameGenerator:
    """英文名字生成器"""
    
    ROOTS = {
        'prefixes': ['Al', 'Bri', 'Car', 'Dan', 'El', 'Fer', 'Gar', 'Har', 'Jes', 'Kar', 
                    'Lar', 'Mar', 'Nor', 'Par', 'Quin', 'Ros', 'Sar', 'Tar', 'Val', 'Wil'],
        'middles': ['an', 'en', 'in', 'on', 'ar', 'er', 'or', 'ur', 'al', 'el', 
                   'il', 'ol', 'am', 'em', 'im', 'om', 'ay', 'ey', 'oy', 'ian'],
        'suffixes': ['ton', 'son', 'man', 'ley', 'field', 'ford', 'wood', 'stone', 'worth', 'berg',
                    'stein', 'bach', 'heim', 'gard', 'land', 'wick', 'shire', 'dale', 'brook', 'ridge'],
        'name_roots': ['Alex', 'Bern', 'Crist', 'Dav', 'Edw', 'Fred', 'Greg', 'Henr', 'Ivan', 'John',
                      'Ken', 'Leon', 'Mich', 'Nick', 'Oliv', 'Paul', 'Rich', 'Step', 'Thom', 'Will'],
        'name_endings': ['a', 'e', 'i', 'o', 'y', 'ie', 'ey', 'an', 'en', 'in', 
                        'on', 'er', 'ar', 'or', 'el', 'al', 'iel', 'ael', 'ine', 'lyn']
    }
    
    PATTERNS = {
        'first_name': [
            ['prefix', 'ending'],
            ['name_root', 'ending'],
            ['prefix', 'middle', 'ending'],
            ['name_root', 'middle', 'ending']
        ],
        'last_name': [
            ['prefix', 'suffix'],
            ['name_root', 'suffix'],
            ['prefix', 'middle', 'suffix'],
            ['compound']
        ]
    }
    
    @classmethod
    def _generate_component(cls, pattern):
        """根据模式生成名字组件"""
        components = []
        for part in pattern:
            if part == 'prefix':
                component = random.choice(cls.ROOTS['prefixes'])
            elif part == 'middle':
                component = random.choice(cls.ROOTS['middles'])
            elif part == 'suffix':
                component = random.choice(cls.ROOTS['suffixes'])
            elif part == 'name_root':
                component = random.choice(cls.ROOTS['name_roots'])
            elif part == 'ending':
                component = random.choice(cls.ROOTS['name_endings'])
            elif part == 'compound':
                part1 = random.choice(cls.ROOTS['prefixes'])
                part2 = random.choice(cls.ROOTS['suffixes'])
                component = part1 + part2
            else:
                component = ''
            
            components.append(component)
        
        return ''.join(components)
    
    @classmethod
    def _format_name(cls, name):
        """格式化名字（首字母大写）"""
        return name.capitalize()
    
    @classmethod
    def generate(cls, realistic=True):
        """
        生成英文名字

        Args:
            realistic: True 用真实常见姓名池（默认，降低风控误判），
                       False 用原来的拼接算法

        Returns:
            dict: 包含 first_name, last_name, full_name
        """
        if realistic:
            first_name = random.choice(REAL_FIRST_NAMES)
            last_name = random.choice(REAL_LAST_NAMES)
            return {
                'first_name': first_name,
                'last_name': last_name,
                'full_name': f"{first_name} {last_name}",
            }

        first_name_pattern = random.choice(cls.PATTERNS['first_name'])
        last_name_pattern = random.choice(cls.PATTERNS['last_name'])
        
        first_name = cls._generate_component(first_name_pattern)
        last_name = cls._generate_component(last_name_pattern)
        
        return {
            'first_name': cls._format_name(first_name),
            'last_name': cls._format_name(last_name),
            'full_name': f"{cls._format_name(first_name)} {cls._format_name(last_name)}"
        }


def generate_email(school_domain='MIT.EDU'):
    """
    生成随机学校邮箱
    
    Args:
        school_domain: 学校域名
    
    Returns:
        str: 邮箱地址
    """
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    username = ''.join(random.choice(chars) for _ in range(8))
    return f"{username}@{school_domain}"


def generate_birth_date():
    """
    生成随机生日（2000-2005年）
    
    Returns:
        str: YYYY-MM-DD 格式的日期
    """
    year = 2000 + random.randint(0, 5)
    month = str(random.randint(1, 12)).zfill(2)
    day = str(random.randint(1, 28)).zfill(2)
    return f"{year}-{month}-{day}"

