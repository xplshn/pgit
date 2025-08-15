document.addEventListener('DOMContentLoaded', () => {
    if (!document.querySelector('.issue-container') && !document.getElementById('new-issue-btn')) {
        return;
    }

    // --- GLOBAL STATE ---
    let isEditing = false; // Mutex to prevent multiple simultaneous edits
    let confirmCallback = null;

    // --- ELEMENTS ---
    const aliasBtn = document.getElementById('alias-btn');
    const aliasModal = document.getElementById('alias-modal');
    const reactionPicker = document.getElementById('reaction-picker');
    const replyTextarea = document.getElementById('reply-textarea');
    const submitCommentBtn = document.getElementById('submit-comment-btn');
    const newIssueBtn = document.getElementById('new-issue-btn');
    const currentUserAliasSpan = document.getElementById('current-user-alias');
    const newIssueModal = document.getElementById('new-issue-modal');
    const submitNewIssueBtn = document.getElementById('submit-new-issue-btn');
    const issueFilterInput = document.getElementById('issue-filter-input');
    const issuesList = document.getElementById('issues-list');

    // --- INITIALIZATION ---
    updateAliasDisplay();
    if (reactionPicker) {
        populateReactionPicker();
    }

    // --- EVENT LISTENERS ---
    document.body.addEventListener('click', handleBodyClick);
    if (aliasBtn) aliasBtn.addEventListener('click', showAliasModal);
    if (submitCommentBtn) submitCommentBtn.addEventListener('click', handleSubmitNewComment);
    if (newIssueBtn) newIssueBtn.addEventListener('click', showNewIssueModal);
    if (submitNewIssueBtn) submitNewIssueBtn.addEventListener('click', handleSubmitNewIssue);
    if (issueFilterInput && issuesList) {
        issueFilterInput.addEventListener('input', filterIssues);
    }

    // --- MODAL & POPUP HANDLING ---
    function handleBodyClick(e) {
        if (e.target.classList.contains('close-btn') || e.target.classList.contains('modal')) {
            const modalId = e.target.dataset.modal || (e.target.closest('.modal')?.id);
            if (modalId) {
                document.getElementById(modalId).style.display = 'none';
            }
        }
        if (e.target.id === 'save-alias-btn') {
            saveAlias();
        }
        const actionBtn = e.target.closest('.action-btn');
        if (actionBtn) {
            handleTimelineAction(actionBtn);
        }
        if (e.target.parentElement?.id === 'reaction-picker') {
            handleReactionSelection(e.target);
        }
        const reactionBadge = e.target.closest('.reaction-badge[data-action="unreact"]');
        if (reactionBadge) {
            handleUnreact(reactionBadge);
        }
        if (e.target.classList.contains('dropdown-toggle')) {
            e.preventDefault();
            toggleDropdown(e.target);
        } else if (!e.target.closest('.dropdown')) {
            document.querySelectorAll('.dropdown-menu').forEach(menu => menu.style.display = 'none');
        }
        if (e.target.classList.contains('mark-as-btn')) {
            e.preventDefault();
            handleMarkAs(e.target);
        }
        if (e.target.id === 'confirm-modal-ok-btn') {
            if (typeof confirmCallback === 'function') {
                confirmCallback();
            }
            document.getElementById('confirm-modal').style.display = 'none';
            confirmCallback = null;
        }
        if (e.target.id === 'confirm-modal-cancel-btn' || e.target.dataset.modal === 'confirm-modal') {
             document.getElementById('confirm-modal').style.display = 'none';
             confirmCallback = null;
        }
        if (reactionPicker && !reactionPicker.contains(e.target) && !e.target.matches('[data-action="react"]')) {
            reactionPicker.style.display = 'none';
        }
    }

    function toggleDropdown(button) {
        const dropdownMenu = button.nextElementSibling;
        const isVisible = dropdownMenu.style.display === 'block';
        document.querySelectorAll('.dropdown-menu').forEach(menu => menu.style.display = 'none');
        dropdownMenu.style.display = isVisible ? 'none' : 'block';
    }

    function showAliasModal() {
        if (aliasModal) {
            document.getElementById('alias-input').value = getCookie('pgit_alias') || '';
            aliasModal.style.display = 'block';
        }
    }

    function showNewIssueModal(e) {
        e.preventDefault();
        if (newIssueModal) {
            newIssueModal.style.display = 'block';
        }
    }

    function showErrorModal(message) {
        const modal = document.getElementById('error-modal');
        if (modal) {
            modal.querySelector('p').textContent = message;
            modal.style.display = 'block';
        } else {
            console.error(message);
        }
    }

    function showConfirmModal(message, onConfirm) {
        const modal = document.getElementById('confirm-modal');
        if (modal) {
            modal.querySelector('#confirm-modal-message').textContent = message;
            confirmCallback = onConfirm;
            modal.style.display = 'block';
        }
    }

    function showReactionPicker(button) {
        if (!reactionPicker) return;
        const rect = button.getBoundingClientRect();
        reactionPicker.style.top = `${window.scrollY + rect.bottom}px`;
        reactionPicker.style.left = `${window.scrollX + rect.left}px`;
        reactionPicker.style.display = 'block';
        const timelineItem = button.closest('.timeline-item');
        reactionPicker.dataset.issueId = timelineItem.dataset.id;
        reactionPicker.dataset.commentId = timelineItem.dataset.type === 'comment' ? timelineItem.dataset.id : '';
        reactionPicker.dataset.type = timelineItem.dataset.type;
    }

    // --- CORE LOGIC ---
    function handleTimelineAction(button) {
        const action = button.dataset.action;
        const item = button.closest('.timeline-item');
        if (!item) return;

        switch (action) {
            case 'edit':
                startEdit(item);
                break;
            case 'quote':
                quoteText(item);
                break;
            case 'react':
                showReactionPicker(button);
                break;
        }
    }

    function handleMarkAs(button) {
        if (!PGB_EMAIL_ADDR) {
            showErrorModal('Cannot perform this action: The repository contact email is not configured.');
            return;
        }
        const issueId = button.dataset.issueId;
        const status = button.dataset.status;

        const subject = `${PGB_SUBJECT_TAG} Mark Issue #${issueId} as ${status}`;
        const mailBody = `---pgitBot---\ncommand: mark-as\nissue-id: ${issueId}\nstatus: ${status}\n---pgitBot---`;
        const mailto = `mailto:${PGB_EMAIL_ADDR}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(mailBody)}`;

        window.location.href = mailto;
    }

    function handleSubmitNewComment() {
        const issueId = document.querySelector('.timeline-item[data-type="issue"]').dataset.id;
        const body = replyTextarea.value;
        if (!body.trim()) return;

        const subject = `${PGB_SUBJECT_TAG} New Comment on Issue #${issueId}`;
        const mailBody = `${body}\n\n---pgitBot---\ncommand: add-comment\nissue-id: ${issueId}\n---pgitBot---`;
        const mailto = `mailto:${PGB_EMAIL_ADDR}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(mailBody)}`;

        window.location.href = mailto;
        replyTextarea.value = '';
    }

    function handleSubmitNewIssue() {
        const titleInput = document.getElementById('new-issue-title');
        const bodyInput = document.getElementById('new-issue-body');
        const title = titleInput.value.trim();
        const body = bodyInput.value.trim();

        if (!title) {
            titleInput.style.borderColor = 'red';
            return;
        }
        titleInput.style.borderColor = '';

        const subject = `${PGB_SUBJECT_TAG} New Issue: ${title}`;
        const mailBody = `${body}\n\n---pgitBot---\ncommand: create-issue\ntitle: ${title}\n---pgitBot---`;
        const mailto = `mailto:${PGB_EMAIL_ADDR}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(mailBody)}`;

        window.location.href = mailto;

        titleInput.value = '';
        bodyInput.value = '';
        if (newIssueModal) {
            newIssueModal.style.display = 'none';
        }
    }

    function startEdit(item) {
        if (isEditing) {
            showErrorModal("Please save or cancel your current edit before editing another item.");
            return;
        }

        const author = item.dataset.author;
        if (getCookie('pgit_author_email') !== author) {
            showConfirmModal("You are trying to edit an item you may not have created. The bot will reject this if you are not the original author. Continue?", () => proceedWithEdit(item));
        } else {
            proceedWithEdit(item);
        }
    }

    function proceedWithEdit(item) {
        isEditing = true;

        const bodyElement = item.querySelector('.comment-body');
        const originalMarkdownElement = item.querySelector('.original-markdown');
        const actionsElement = item.querySelector('.comment-actions');

        bodyElement.style.display = 'none';
        actionsElement.style.display = 'none';

        const editorTextarea = document.createElement('textarea');
        editorTextarea.className = 'comment-editor';
        editorTextarea.value = originalMarkdownElement.textContent;
        item.querySelector('.comment-box').insertBefore(editorTextarea, bodyElement.nextSibling);
        editorTextarea.focus();

        const controlsDiv = document.createElement('div');
        controlsDiv.className = 'comment-edit-controls';

        const saveBtn = document.createElement('button');
        saveBtn.className = 'btn';
        saveBtn.textContent = 'Save';

        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn btn-secondary';
        cancelBtn.textContent = 'Cancel';

        controlsDiv.appendChild(cancelBtn);
        controlsDiv.appendChild(saveBtn);
        editorTextarea.insertAdjacentElement('afterend', controlsDiv);

        const cancelEdit = () => {
            editorTextarea.remove();
            controlsDiv.remove();
            bodyElement.style.display = 'block';
            actionsElement.style.display = 'flex';
            isEditing = false;
        };

        cancelBtn.addEventListener('click', cancelEdit);

        saveBtn.addEventListener('click', () => {
            const newBody = editorTextarea.value;
            if (!newBody.trim()) return;

            const type = item.dataset.type;
            const id = item.dataset.id;
            const issueId = (type === 'issue') ? id : item.closest('.issue-container').querySelector('.timeline-item[data-type="issue"]').dataset.id;

            const subject = `${PGB_SUBJECT_TAG} Edit ${type} on Issue #${issueId}`;
            let mailBody = `${newBody}\n\n---pgitBot---\ncommand: edit\nissue-id: ${issueId}\ntype: ${type}\n`;
            if (type === 'comment') {
                mailBody += `comment-id: ${id}\n`;
            }
            mailBody += `---pgitBot---`;
            const mailto = `mailto:${PGB_EMAIL_ADDR}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(mailBody)}`;
            window.location.href = mailto;

            cancelEdit();
        });
    }

    function quoteText(item) {
        if (!replyTextarea) return;
        const originalMarkdownElement = item.querySelector('.original-markdown');
        const author = item.querySelector('.author strong').textContent;
        const selection = window.getSelection().toString();
        const textToQuote = selection || originalMarkdownElement.textContent;

        const quotedText = `> ${textToQuote.replace(/\n/g, '\n> ')}\n\n*Quoting ${author}*\n\n`;

        replyTextarea.value = quotedText + replyTextarea.value;
        replyTextarea.focus();
        replyTextarea.setSelectionRange(replyTextarea.value.length, replyTextarea.value.length);
    }

    function handleReactionSelection(target) {
        const reactionName = target.dataset.reaction;
        if (!reactionName || !reactionPicker) return;

        const issueId = reactionPicker.dataset.issueId;
        const commentId = reactionPicker.dataset.commentId;
        const type = reactionPicker.dataset.type;

        const subject = `${PGB_SUBJECT_TAG} React to ${type} on Issue #${issueId}`;
        let mailBody = `---pgitBot---\ncommand: react\nissue-id: ${issueId}\ntype: ${type}\nreaction: ${reactionName}\n`;
        if (type === 'comment') {
            mailBody += `comment-id: ${commentId}\n`;
        }
        mailBody += `---pgitBot---`;

        const mailto = `mailto:${PGB_EMAIL_ADDR}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(mailBody)}`;
        window.location.href = mailto;

        reactionPicker.style.display = 'none';
    }

    function handleUnreact(button) {
        const reactionName = button.dataset.reactionName;
        if (!reactionName) return;

        const timelineItem = button.closest('.timeline-item');
        if (!timelineItem) return;

        showConfirmModal(`Send email to remove your "${reactionName}" reaction?`, () => {
            const type = timelineItem.dataset.type;
            const issueId = (type === 'issue') ? timelineItem.dataset.id : button.closest('.issue-container').querySelector('.timeline-item[data-type="issue"]').dataset.id;
            const commentId = (type === 'comment') ? timelineItem.dataset.id : '';

            const subject = `${PGB_SUBJECT_TAG} Un-react to ${type} on Issue #${issueId}`;
            let mailBody = `---pgitBot---\ncommand: unreact\nissue-id: ${issueId}\ntype: ${type}\nreaction: ${reactionName}\n`;
            if (type === 'comment') {
                mailBody += `comment-id: ${commentId}\n`;
            }
            mailBody += `---pgitBot---`;

            const mailto = `mailto:${PGB_EMAIL_ADDR}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(mailBody)}`;
            window.location.href = mailto;
        });
    }

    function saveAlias() {
        const aliasInput = document.getElementById('alias-input');
        const newAlias = aliasInput.value.trim();

        const subject = `${PGB_SUBJECT_TAG} Set Alias`;
        const command = newAlias === '' ? 'unalias' : 'alias';
        let mailBody = `---pgitBot---\ncommand: ${command}\n`;
        if (command === 'alias') {
            mailBody += `alias: ${newAlias}\n`;
        }
        mailBody += `---pgitBot---`;

        const mailto = `mailto:${PGB_EMAIL_ADDR}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(mailBody)}`;
        window.location.href = mailto;

        setCookie('pgit_alias', newAlias || 'anonymous', 365);
        updateAliasDisplay();
        if (aliasModal) aliasModal.style.display = 'none';
    }

    function updateAliasDisplay() {
        if (currentUserAliasSpan) {
            currentUserAliasSpan.textContent = `Commenting as ${getCookie('pgit_alias') || 'anonymous'}`;
        }
    }

    function populateReactionPicker() {
        if (!reactionPicker) return;
        let html = '';
        for (const name in PGB_REACTIONS) {
            html += `<button class="reaction-picker-emoji" data-reaction="${name}" title="${name}">${PGB_REACTIONS[name]}</button>`;
        }
        reactionPicker.innerHTML = html;
    }

    function setCookie(name, value, days) {
        let expires = "";
        if (days) {
            const date = new Date();
            date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
            expires = "; expires=" + date.toUTCString();
        }
        document.cookie = name + "=" + (value || "") + expires + "; path=/; SameSite=Lax";
    }

    function getCookie(name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) == ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
        }
        return null;
    }

    function filterIssues() {
        const filterText = issueFilterInput.value.toLowerCase();
        const issueItems = issuesList.querySelectorAll('.issue-list-item');
        issueItems.forEach(item => {
            const title = item.dataset.issueTitle.toLowerCase();
            if (title.includes(filterText)) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    }
});
