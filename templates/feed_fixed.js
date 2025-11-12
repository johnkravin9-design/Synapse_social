<script>
    let posts = [];
    let stories = [];
    let reels = [];
    let currentStoryIndex = 0;

    // Load feed on page load
    window.addEventListener('load', async () => {
        await loadStories();
        await loadPosts();
        await loadReels();
        startLiveActivity();
    });

    async function loadStories() {
        try {
            // Use public endpoint for development
            const response = await fetch('/api/public/stories');
            const result = await response.json();
            stories = result.stories || [];
            renderStories();
        } catch (error) {
            console.error('Error loading stories:', error);
            stories = [];
            renderStories();
        }
    }

    async function loadPosts() {
        try {
            // Use public endpoint for development
            const response = await fetch('/api/public/posts');
            const result = await response.json();
            posts = result.posts || [];
            renderPosts();
        } catch (error) {
            console.error('Error loading posts:', error);
            posts = [];
            renderPosts();
        }
    }

    async function loadReels() {
        try {
            // Use public endpoint for development
            const response = await fetch('/api/public/reels');
            const result = await response.json();
            reels = result.reels || [];
            renderReels();
        } catch (error) {
            console.error('Error loading reels:', error);
            reels = [];
            renderReels();
        }
    }

    function renderStories() {
        const container = document.getElementById('stories-container');
        if (!container) return;
        
        // Add create story button
        let storiesHTML = `
            <div class="flex-shrink-0 text-center">
                <button onclick="openCreateStory()" class="story-circle">
                    <div class="story-inner w-16 h-16 flex items-center justify-center bg-gradient-to-br from-purple-600 to-pink-600 rounded-full border-2 border-white">
                        <i class="fas fa-plus text-2xl text-white"></i>
                    </div>
                </button>
                <p class="text-xs mt-1">Create</p>
            </div>
        `;
        
        // Add existing stories
        storiesHTML += stories.map((story, index) => `
            <div class="flex-shrink-0 text-center">
                <button onclick="openStory(${index})" class="story-circle">
                    <div class="story-inner w-16 h-16 flex items-center justify-center bg-gradient-to-br from-blue-500 to-green-500 rounded-full border-2 border-white">
                        ${story.user.avatar || '👤'}
                    </div>
                </button>
                <p class="text-xs mt-1 truncate w-16">${story.user.name || 'User'}</p>
            </div>
        `).join('');
        
        container.innerHTML = storiesHTML;
    }

    function renderPosts() {
        const container = document.getElementById('posts-container');
        if (!container) return;
        
        if (posts.length === 0) {
            container.innerHTML = `
                <div class="glass-effect rounded-xl p-8 text-center">
                    <div class="text-4xl mb-4">📝</div>
                    <h3 class="text-xl font-bold mb-2">No Posts Yet</h3>
                    <p class="text-gray-400">Be the first to create a post!</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = posts.map(post => `
            <div class="glass-effect rounded-xl p-4">
                <div class="flex items-center space-x-3 mb-3">
                    <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-green-500 rounded-full flex items-center justify-center text-white font-bold">
                        ${post.user.avatar || '👤'}
                    </div>
                    <div>
                        <h4 class="font-bold">${post.user.username || 'User'}</h4>
                        <p class="text-xs text-gray-400">${new Date(post.created_at).toLocaleString()}</p>
                    </div>
                </div>
                <p class="mb-3">${post.content}</p>
                <div class="flex space-x-4 text-sm text-gray-400">
                    <button onclick="likePost(${post.id}, 'post')" class="flex items-center space-x-1 hover:text-red-500 transition">
                        <i class="fas fa-heart"></i>
                        <span>${post.likes_count || 0}</span>
                    </button>
                    <button onclick="toggleComments(${post.id})" class="flex items-center space-x-1 hover:text-blue-500 transition">
                        <i class="fas fa-comment"></i>
                        <span>${post.comments_count || 0}</span>
                    </button>
                    <button onclick="sharePost(${post.id})" class="flex items-center space-x-1 hover:text-green-500 transition">
                        <i class="fas fa-share"></i>
                        <span>Share</span>
                    </button>
                </div>
                
                <!-- Comments Section -->
                <div id="comments-${post.id}" class="mt-3 hidden">
                    <div class="flex space-x-2 mb-2">
                        <input type="text" id="comment-input-${post.id}" placeholder="Add a comment..." class="flex-1 bg-white bg-opacity-10 rounded-lg px-3 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-purple-500">
                        <button onclick="addComment(${post.id}, 'post')" class="bg-purple-600 text-white px-3 py-1 rounded-lg text-sm hover:bg-purple-700 transition">Post</button>
                    </div>
                    <div id="comments-list-${post.id}" class="space-y-2 text-sm"></div>
                </div>
            </div>
        `).join('');
    }

    // Basic interaction functions
    function likePost(postId, type) {
        alert(`Liked ${type} ${postId}`);
        // In production, make API call to /api/like
    }

    function toggleComments(postId) {
        const commentsSection = document.getElementById(`comments-${postId}`);
        commentsSection.classList.toggle('hidden');
    }

    function addComment(postId, type) {
        const commentInput = document.getElementById(`comment-input-${postId}`);
        const comment = commentInput.value.trim();
        
        if (comment) {
            alert(`Comment added to ${type} ${postId}: ${comment}`);
            commentInput.value = '';
            // In production, make API call to /api/comment
        }
    }

    function sharePost(postId) {
        if (navigator.share) {
            navigator.share({
                title: 'Check this post!',
                text: 'Interesting post from Synapse Social',
                url: window.location.href
            });
        } else {
            alert('Share link copied to clipboard!');
        }
    }

    function startLiveActivity() {
        // Simulate live updates
        setInterval(() => {
            console.log('Live activity running...');
        }, 30000);
    }

    // API request helper
    async function apiRequest(url, method = 'GET', data = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
        };

        if (data && (method === 'POST' || method === 'PUT')) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(url, options);
        return await response.json();
    }
</script>
