const DIRECTORIES = {
    worlds: 'public/worlds/',
    user: 'public/user',
    avatars: 'public/User Avatars',
    images: 'public/img/',
    userImages: 'public/user/images/',
    groups: 'public/groups/',
    groupChats: 'public/group chats',
    chats: 'public/chats/',
    characters: 'public/characters/',
    backgrounds: 'public/backgrounds',
    novelAI_Settings: 'public/NovelAI Settings',
    koboldAI_Settings: 'public/KoboldAI Settings',
    openAI_Settings: 'public/OpenAI Settings',
    textGen_Settings: 'public/TextGen Settings',
    thumbnails: 'thumbnails/',
    thumbnailsBg: 'thumbnails/bg/',
    thumbnailsAvatar: 'thumbnails/avatar/',
    themes: 'public/themes',
    movingUI: 'public/movingUI',
    extensions: 'public/scripts/extensions',
    instruct: 'public/instruct',
    context: 'public/context',
    backups: 'backups/',
    quickreplies: 'public/QuickReplies',
    assets: 'public/assets',
    comfyWorkflows: 'public/user/workflows',
    files: 'public/user/files',
    sounds: 'public/sounds',
};

const UNSAFE_EXTENSIONS = [
    '.php',
    '.exe',
    '.com',
    '.dll',
    '.pif',
    '.application',
    '.gadget',
    '.msi',
    '.jar',
    '.cmd',
    '.bat',
    '.reg',
    '.sh',
    '.py',
    '.js',
    '.jse',
    '.jsp',
    '.pdf',
    '.html',
    '.htm',
    '.hta',
    '.vb',
    '.vbs',
    '.vbe',
    '.cpl',
    '.msc',
    '.scr',
    '.sql',
    '.iso',
    '.img',
    '.dmg',
    '.ps1',
    '.ps1xml',
    '.ps2',
    '.ps2xml',
    '.psc1',
    '.psc2',
    '.msh',
    '.msh1',
    '.msh2',
    '.mshxml',
    '.msh1xml',
    '.msh2xml',
    '.scf',
    '.lnk',
    '.inf',
    '.reg',
    '.doc',
    '.docm',
    '.docx',
    '.dot',
    '.dotm',
    '.dotx',
    '.xls',
    '.xlsm',
    '.xlsx',
    '.xlt',
    '.xltm',
    '.xltx',
    '.xlam',
    '.ppt',
    '.pptm',
    '.pptx',
    '.pot',
    '.potm',
    '.potx',
    '.ppam',
    '.ppsx',
    '.ppsm',
    '.pps',
    '.ppam',
    '.sldx',
    '.sldm',
    '.ws',
];

const GEMINI_SAFETY = [
    {
        category: 'HARM_CATEGORY_HARASSMENT',
        threshold: 'BLOCK_NONE',
    },
    {
        category: 'HARM_CATEGORY_HATE_SPEECH',
        threshold: 'BLOCK_NONE',
    },
    {
        category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT',
        threshold: 'BLOCK_NONE',
    },
    {
        category: 'HARM_CATEGORY_DANGEROUS_CONTENT',
        threshold: 'BLOCK_NONE',
    },
];

const BISON_SAFETY = [
    {
        category: 'HARM_CATEGORY_DEROGATORY',
        threshold: 'BLOCK_NONE',
    },
    {
        category: 'HARM_CATEGORY_TOXICITY',
        threshold: 'BLOCK_NONE',
    },
    {
        category: 'HARM_CATEGORY_VIOLENCE',
        threshold: 'BLOCK_NONE',
    },
    {
        category: 'HARM_CATEGORY_SEXUAL',
        threshold: 'BLOCK_NONE',
    },
    {
        category: 'HARM_CATEGORY_MEDICAL',
        threshold: 'BLOCK_NONE',
    },
    {
        category: 'HARM_CATEGORY_DANGEROUS',
        threshold: 'BLOCK_NONE',
    },
];

const CHAT_COMPLETION_SOURCES = {
    OPENAI: 'openai',
    WINDOWAI: 'windowai',
    CLAUDE: 'claude',
    SCALE: 'scale',
    OPENROUTER: 'openrouter',
    AI21: 'ai21',
    MAKERSUITE: 'makersuite',
    MISTRALAI: 'mistralai',
    CUSTOM: 'custom',
};

const UPLOADS_PATH = './uploads';

// TODO: this is copied from the client code; there should be a way to de-duplicate it eventually
const TEXTGEN_TYPES = {
    OOBA: 'ooba',
    MANCER: 'mancer',
    APHRODITE: 'aphrodite',
    TABBY: 'tabby',
    KOBOLDCPP: 'koboldcpp',
    TOGETHERAI: 'togetherai',
    LLAMACPP: 'llamacpp',
    OLLAMA: 'ollama',
    INFERMATICAI: 'infermaticai',
    DREAMGEN: 'dreamgen',
    OPENROUTER: 'openrouter',
};

const INFERMATICAI_KEYS = [
    'model',
    'prompt',
    'max_tokens',
    'temperature',
    'top_p',
    'top_k',
    'repetition_penalty',
    'stream',
    'stop',
];

// https://dreamgen.com/docs/api#openai-text
const DREAMGEN_KEYS = [
    'model',
    'prompt',
    'max_tokens',
    'temperature',
    'top_p',
    'top_k',
    'min_p',
    'repetition_penalty',
    'frequency_penalty',
    'presence_penalty',
    'stop',
    'stream',
    'minimum_message_content_tokens'
];

// https://docs.together.ai/reference/completions
const TOGETHERAI_KEYS = [
    'model',
    'prompt',
    'max_tokens',
    'temperature',
    'top_p',
    'top_k',
    'repetition_penalty',
    'stream',
    'stop',
];

// https://github.com/jmorganca/ollama/blob/main/docs/api.md#request-with-options
const OLLAMA_KEYS = [
    'num_predict',
    'stop',
    'temperature',
    'repeat_penalty',
    'presence_penalty',
    'frequency_penalty',
    'top_k',
    'top_p',
    'tfs_z',
    'typical_p',
    'seed',
    'repeat_last_n',
    'mirostat',
    'mirostat_tau',
    'mirostat_eta',
];

const AVATAR_WIDTH = 400;
const AVATAR_HEIGHT = 600;

const OPENROUTER_HEADERS = {
    'HTTP-Referer': 'https://sillytavern.app',
    'X-Title': 'SillyTavern',
};

const OPENROUTER_KEYS = [
    'max_tokens',
    'temperature',
    'top_k',
    'top_p',
    'presence_penalty',
    'frequency_penalty',
    'repetition_penalty',
    'min_p',
    'top_a',
    'seed',
    'logit_bias',
    'model',
    'stream',
    'prompt',
    'stop',
];

module.exports = {
    DIRECTORIES,
    UNSAFE_EXTENSIONS,
    UPLOADS_PATH,
    GEMINI_SAFETY,
    BISON_SAFETY,
    TEXTGEN_TYPES,
    CHAT_COMPLETION_SOURCES,
    AVATAR_WIDTH,
    AVATAR_HEIGHT,
    TOGETHERAI_KEYS,
    OLLAMA_KEYS,
    INFERMATICAI_KEYS,
    DREAMGEN_KEYS,
    OPENROUTER_HEADERS,
    OPENROUTER_KEYS,
};
