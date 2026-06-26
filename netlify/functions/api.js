// =============================================
// CORTIS FANBASE - Netlify Function: api.js
// Letakkan file ini di: netlify/functions/api.js
// =============================================
// DEPENDENCIES (package.json harus ada di root):
// npm install @supabase/supabase-js jsonwebtoken bcryptjs cookie
// =============================================

const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookie = require('cookie');

// == KONFIGURASI (isi di Netlify Environment Variables) ==
const SUPABASE_URL  = process.env.SUPABASE_URL;
const SUPABASE_KEY  = process.env.SUPABASE_SERVICE_KEY; // pakai Service Role Key
const JWT_SECRET    = process.env.JWT_SECRET;            // string acak panjang
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*'; // e.g. https://situmu.netlify.app

// ============= HELPER =============
function respond(statusCode, body, extraHeaders = {}) {
    return {
        statusCode,
        headers: {
            'Content-Type': 'application/json',
            // FIX: Jangan pakai '*' jika menggunakan credentials.
            // Set ALLOWED_ORIGIN di env vars ke domain Netlify kamu.
            'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
            ...extraHeaders,
        },
        body: JSON.stringify(body),
    };
}

function setCookieHeader(token) {
    return cookie.serialize('token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        maxAge: 60 * 60 * 24 * 7, // 7 hari
        path: '/',
    });
}

function clearCookieHeader() {
    return cookie.serialize('token', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        maxAge: 0,
        path: '/',
    });
}

function getTokenFromCookie(event) {
    const cookies = cookie.parse(event.headers.cookie || '');
    return cookies.token || null;
}

function verifyToken(token) {
    try { return jwt.verify(token, JWT_SECRET); }
    catch { return null; }
}

async function getCurrentUser(event, supabase) {
    const token = getTokenFromCookie(event);
    if (!token) return null;
    const decoded = verifyToken(token);
    if (!decoded) return null;
    const { data } = await supabase.from('users').select('*').eq('id', decoded.id).single();
    if (!data || data.banned) return null;
    return data;
}

// ============= HANDLER UTAMA =============
exports.handler = async (event) => {
    // FIX: Validasi env vars sebelum melanjutkan
    if (!SUPABASE_URL || !SUPABASE_KEY || !JWT_SECRET) {
        return respond(500, { error: 'Konfigurasi server tidak lengkap. Set env vars di Netlify.' });
    }

    // FIX: Inisialisasi supabase di dalam handler agar tidak crash saat cold start
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    // Handle preflight CORS
    if (event.httpMethod === 'OPTIONS') {
        return respond(200, {});
    }

    // Ambil path setelah /api/
    const rawPath = event.path.replace('/.netlify/functions/api', '');
    const path    = rawPath.replace(/^\/+/, ''); // hapus leading slash
    const method  = event.httpMethod;
    let body = {};
    try { body = JSON.parse(event.body || '{}'); } catch {}

    const pathParts = path.split('/'); // e.g. ['member', '5']

    // ============= AUTH =============
    // POST /register
    if (method === 'POST' && path === 'register') {
        const { username, email, password } = body;
        if (!username || !email || !password) return respond(400, { error: 'Semua field wajib diisi' });
        if (password.length < 4) return respond(400, { error: 'Password minimal 4 karakter' });

        // FIX: Pisahkan query agar aman dari injection karakter khusus
        const { data: existingUser } = await supabase.from('users').select('id').eq('username', username).maybeSingle();
        const { data: existingEmail } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
        if (existingUser || existingEmail) return respond(400, { error: 'Username atau email sudah digunakan' });

        const hashed = await bcrypt.hash(password, 10);
        const { error } = await supabase.from('users').insert({ username, email, password: hashed, role: 'user', banned: false });
        if (error) return respond(500, { error: 'Gagal mendaftar' });
        return respond(201, { message: 'Registrasi berhasil!' });
    }

    // POST /login
    if (method === 'POST' && path === 'login') {
        const { username, password } = body;
        if (!username || !password) return respond(400, { error: 'Username dan password wajib diisi' });

        // FIX: Pisahkan query agar aman dari injection
        const { data: userByUsername } = await supabase.from('users').select('*').eq('username', username).maybeSingle();
        const { data: userByEmail } = !userByUsername
            ? await supabase.from('users').select('*').eq('email', username).maybeSingle()
            : { data: null };

        const user = userByUsername || userByEmail;
        if (!user) return respond(401, { error: 'Username atau password salah' });
        if (user.banned) return respond(403, { error: 'Akun Anda telah di-ban' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return respond(401, { error: 'Username atau password salah' });

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        return respond(200,
            { message: 'Login berhasil', user: { id: user.id, username: user.username, role: user.role } },
            { 'Set-Cookie': setCookieHeader(token) }
        );
    }

    // POST /logout
    if (method === 'POST' && path === 'logout') {
        return respond(200, { message: 'Logout berhasil' }, { 'Set-Cookie': clearCookieHeader() });
    }

    // GET /me
    if (method === 'GET' && path === 'me') {
        const user = await getCurrentUser(event, supabase);
        if (!user) return respond(401, { error: 'Belum login' });
        return respond(200, { user: { id: user.id, username: user.username, role: user.role } });
    }

    // ============= MEMBERS =============
    // GET /members
    if (method === 'GET' && path === 'members') {
        const { data } = await supabase.from('members').select('*').order('id');
        return respond(200, data || []);
    }

    // GET /member/:id  (singular — dipakai oleh openEditModal di frontend)
    if (method === 'GET' && pathParts[0] === 'member' && pathParts[1]) {
        const { data } = await supabase.from('members').select('*').eq('id', pathParts[1]).single();
        return respond(200, data || {});
    }

    // POST /members
    if (method === 'POST' && path === 'members') {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { name, role: memberRole, bio, photo } = body;
        if (!name) return respond(400, { error: 'Nama wajib diisi' });
        const { error } = await supabase.from('members').insert({ name, role: memberRole, bio, photo });
        if (error) return respond(500, { error: 'Gagal menambah member' });
        return respond(201, { message: 'Member berhasil ditambahkan' });
    }

    // PUT /members/:id
    if (method === 'PUT' && pathParts[0] === 'members' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { name, role: memberRole, bio, photo } = body;
        const { error } = await supabase.from('members').update({ name, role: memberRole, bio, photo }).eq('id', pathParts[1]);
        if (error) return respond(500, { error: 'Gagal mengupdate member' });
        return respond(200, { message: 'Member berhasil diupdate' });
    }

    // DELETE /members/:id
    if (method === 'DELETE' && pathParts[0] === 'members' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        await supabase.from('members').delete().eq('id', pathParts[1]);
        return respond(200, { message: 'Member berhasil dihapus' });
    }

    // ============= GALLERY =============
    // GET /gallery
    if (method === 'GET' && path === 'gallery') {
        const { data } = await supabase.from('gallery').select('*').order('uploaded_at', { ascending: false });
        return respond(200, data || []);
    }

    // GET /gallery/search?q=...
    if (method === 'GET' && path === 'gallery/search') {
        const q = event.queryStringParameters?.q || '';
        const { data } = await supabase.from('gallery').select('*')
            .or(`title.ilike.%${q}%,caption.ilike.%${q}%`).order('uploaded_at', { ascending: false });
        return respond(200, data || []);
    }

    // GET /gallery/:id
    if (method === 'GET' && pathParts[0] === 'gallery' && pathParts[1] && pathParts[1] !== 'search') {
        const { data } = await supabase.from('gallery').select('*').eq('id', pathParts[1]).single();
        return respond(200, data || {});
    }

    // POST /gallery/upload
    if (method === 'POST' && path === 'gallery/upload') {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { title, filename, caption } = body;
        if (!filename) return respond(400, { error: 'URL gambar wajib diisi' });
        const { error } = await supabase.from('gallery').insert({ title, filename, caption, uploaded_at: new Date().toISOString() });
        if (error) return respond(500, { error: 'Gagal menambah foto' });
        return respond(201, { message: 'Foto berhasil ditambahkan' });
    }

    // PUT /gallery/:id
    if (method === 'PUT' && pathParts[0] === 'gallery' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { title, caption, filename } = body;
        await supabase.from('gallery').update({ title, caption, filename }).eq('id', pathParts[1]);
        return respond(200, { message: 'Foto berhasil diupdate' });
    }

    // DELETE /gallery/:id
    if (method === 'DELETE' && pathParts[0] === 'gallery' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        await supabase.from('gallery').delete().eq('id', pathParts[1]);
        return respond(200, { message: 'Foto berhasil dihapus' });
    }

    // ============= NEWS =============
    // GET /news
    if (method === 'GET' && path === 'news') {
        const { data } = await supabase.from('news').select('*').order('date', { ascending: false });
        return respond(200, data || []);
    }

    // GET /news/search?q=...
    if (method === 'GET' && path === 'news/search') {
        const q = event.queryStringParameters?.q || '';
        const { data } = await supabase.from('news').select('*')
            .or(`title.ilike.%${q}%,content.ilike.%${q}%`).order('date', { ascending: false });
        return respond(200, data || []);
    }

    // GET /news/:id
    if (method === 'GET' && pathParts[0] === 'news' && pathParts[1] && pathParts[1] !== 'search') {
        const { data } = await supabase.from('news').select('*').eq('id', pathParts[1]).single();
        return respond(200, data || {});
    }

    // POST /news
    if (method === 'POST' && path === 'news') {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { title, content, date } = body;
        if (!title || !content) return respond(400, { error: 'Judul dan isi wajib diisi' });
        const { error } = await supabase.from('news').insert({ title, content, date: date || new Date().toISOString().split('T')[0] });
        if (error) return respond(500, { error: 'Gagal menambah berita' });
        return respond(201, { message: 'Berita berhasil ditambahkan' });
    }

    // PUT /news/:id
    if (method === 'PUT' && pathParts[0] === 'news' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { title, content, date } = body;
        await supabase.from('news').update({ title, content, date }).eq('id', pathParts[1]);
        return respond(200, { message: 'Berita berhasil diupdate' });
    }

    // DELETE /news/:id
    if (method === 'DELETE' && pathParts[0] === 'news' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        await supabase.from('news').delete().eq('id', pathParts[1]);
        return respond(200, { message: 'Berita berhasil dihapus' });
    }

    // ============= SOCIAL MEDIA =============
    // GET /social
    if (method === 'GET' && path === 'social') {
        const { data } = await supabase.from('social').select('*').order('id');
        return respond(200, data || []);
    }

    // GET /social/:id
    if (method === 'GET' && pathParts[0] === 'social' && pathParts[1]) {
        const { data } = await supabase.from('social').select('*').eq('id', pathParts[1]).single();
        return respond(200, data || {});
    }

    // POST /social
    if (method === 'POST' && path === 'social') {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { platform, url, embed_code, caption } = body;
        if (!url) return respond(400, { error: 'URL wajib diisi' });
        await supabase.from('social').insert({ platform, url, embed_code, caption });
        return respond(201, { message: 'Sosial media berhasil ditambahkan' });
    }

    // PUT /social/:id
    if (method === 'PUT' && pathParts[0] === 'social' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { platform, url, embed_code, caption } = body;
        await supabase.from('social').update({ platform, url, embed_code, caption }).eq('id', pathParts[1]);
        return respond(200, { message: 'Berhasil diupdate' });
    }

    // DELETE /social/:id
    if (method === 'DELETE' && pathParts[0] === 'social' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        await supabase.from('social').delete().eq('id', pathParts[1]);
        return respond(200, { message: 'Berhasil dihapus' });
    }

    // ============= MUSIC =============
    // GET /music
    if (method === 'GET' && path === 'music') {
        const { data } = await supabase.from('music').select('*').order('id');
        return respond(200, data || []);
    }

    // GET /music/:id
    if (method === 'GET' && pathParts[0] === 'music' && pathParts[1]) {
        const { data } = await supabase.from('music').select('*').eq('id', pathParts[1]).single();
        return respond(200, data || {});
    }

    // FIX: Endpoint upload musik diselaraskan dengan frontend (POST /music/upload)
    if (method === 'POST' && path === 'music/upload') {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { title, filename, filepath } = body;
        if (!filepath) return respond(400, { error: 'URL file MP3 wajib diisi' });
        const { error } = await supabase.from('music').insert({ title, filename, filepath });
        if (error) return respond(500, { error: 'Gagal menambah lagu' });
        return respond(201, { message: 'Lagu berhasil ditambahkan' });
    }

    // PUT /music/:id
    if (method === 'PUT' && pathParts[0] === 'music' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { title } = body;
        await supabase.from('music').update({ title }).eq('id', pathParts[1]);
        return respond(200, { message: 'Berhasil diupdate' });
    }

    // DELETE /music/:id
    if (method === 'DELETE' && pathParts[0] === 'music' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        await supabase.from('music').delete().eq('id', pathParts[1]);
        return respond(200, { message: 'Lagu berhasil dihapus' });
    }

    // ============= BACKGROUND =============
    // FIX: Endpoint diselaraskan dengan frontend (/settings/background)
    // GET /settings/background
    if (method === 'GET' && path === 'settings/background') {
        const { data } = await supabase.from('settings').select('value').eq('key', 'background').maybeSingle();
        return respond(200, { background: data?.value || '' });
    }

    // POST /settings/background
    if (method === 'POST' && path === 'settings/background') {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const { background } = body;
        if (!background) return respond(400, { error: 'URL background wajib diisi' });
        await supabase.from('settings').upsert({ key: 'background', value: background });
        return respond(200, { message: 'Background berhasil diupdate' });
    }

    // ============= FORUM =============
    // GET /forum
    if (method === 'GET' && path === 'forum') {
        const { data } = await supabase.from('forum').select('*').order('created_at');
        return respond(200, data || []);
    }

    // GET /forum/search?q=...
    if (method === 'GET' && path === 'forum/search') {
        const q = event.queryStringParameters?.q || '';
        const { data } = await supabase.from('forum').select('*')
            .or(`message.ilike.%${q}%,username.ilike.%${q}%`).order('created_at');
        return respond(200, data || []);
    }

    // POST /forum
    if (method === 'POST' && path === 'forum') {
        const user = await getCurrentUser(event, supabase);
        if (!user) return respond(401, { error: 'Login dulu untuk posting' });
        const { message, parent_id } = body;
        if (!message?.trim()) return respond(400, { error: 'Pesan tidak boleh kosong' });
        const { error } = await supabase.from('forum').insert({
            username: user.username,
            user_id: user.id,
            message: message.trim(),
            parent_id: parent_id || 0,
            created_at: new Date().toISOString(),
        });
        if (error) return respond(500, { error: 'Gagal posting' });
        return respond(201, { message: 'Berhasil diposting' });
    }

    // DELETE /forum/:id
    if (method === 'DELETE' && pathParts[0] === 'forum' && pathParts[1]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        await supabase.from('forum').delete().or(`id.eq.${pathParts[1]},parent_id.eq.${pathParts[1]}`);
        return respond(200, { message: 'Postingan berhasil dihapus' });
    }

    // ============= STATS (Admin) =============
    // GET /stats
    if (method === 'GET' && path === 'stats') {
        const user = await getCurrentUser(event, supabase);
        if (!user || !['admin','super_admin'].includes(user.role)) return respond(403, { error: 'Akses ditolak' });
        const [forum, news, gallery, members, social, music, users] = await Promise.all([
            supabase.from('forum').select('id', { count: 'exact', head: true }),
            supabase.from('news').select('id', { count: 'exact', head: true }),
            supabase.from('gallery').select('id', { count: 'exact', head: true }),
            supabase.from('members').select('id', { count: 'exact', head: true }),
            supabase.from('social').select('id', { count: 'exact', head: true }),
            supabase.from('music').select('id', { count: 'exact', head: true }),
            user.role === 'super_admin'
                ? supabase.from('users').select('id', { count: 'exact', head: true })
                : Promise.resolve({ count: '🔒' }),
        ]);
        return respond(200, {
            forumPosts: forum.count,
            news: news.count,
            gallery: gallery.count,
            members: members.count,
            social: social.count,
            music: music.count,
            users: users.count,
        });
    }

    // ============= USER MANAGEMENT (Super Admin only) =============
    // GET /admin/users
    if (method === 'GET' && path === 'admin/users') {
        const user = await getCurrentUser(event, supabase);
        if (!user || user.role !== 'super_admin') return respond(403, { error: 'Akses ditolak' });
        const { data } = await supabase.from('users').select('id,username,email,role,banned,created_at').order('id');
        return respond(200, data || []);
    }

    // PUT /admin/users/:id/role
    if (method === 'PUT' && pathParts[0] === 'admin' && pathParts[1] === 'users' && pathParts[3] === 'role') {
        const user = await getCurrentUser(event, supabase);
        if (!user || user.role !== 'super_admin') return respond(403, { error: 'Akses ditolak' });
        const { role } = body;
        const allowedRoles = ['user', 'admin'];
        if (!allowedRoles.includes(role)) return respond(400, { error: 'Role tidak valid' });
        await supabase.from('users').update({ role }).eq('id', pathParts[2]);
        return respond(200, { message: 'Role berhasil diupdate' });
    }

    // PUT /admin/users/:id/ban
    if (method === 'PUT' && pathParts[0] === 'admin' && pathParts[1] === 'users' && pathParts[3] === 'ban') {
        const user = await getCurrentUser(event, supabase);
        if (!user || user.role !== 'super_admin') return respond(403, { error: 'Akses ditolak' });
        const { banned } = body;
        await supabase.from('users').update({ banned: !!banned }).eq('id', pathParts[2]);
        return respond(200, { message: banned ? 'User berhasil di-ban' : 'User berhasil di-unban' });
    }

    // DELETE /admin/users/:id
    if (method === 'DELETE' && pathParts[0] === 'admin' && pathParts[1] === 'users' && pathParts[2]) {
        const user = await getCurrentUser(event, supabase);
        if (!user || user.role !== 'super_admin') return respond(403, { error: 'Akses ditolak' });
        // Cegah super_admin menghapus dirinya sendiri
        if (String(pathParts[2]) === String(user.id)) return respond(403, { error: 'Tidak bisa menghapus akun sendiri' });
        await supabase.from('users').delete().eq('id', pathParts[2]);
        return respond(200, { message: 'User berhasil dihapus' });
    }

    // ============= 404 =============
    return respond(404, { error: `Route tidak ditemukan: ${method} /${path}` });
};
