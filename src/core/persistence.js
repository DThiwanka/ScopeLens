/**
 * ScopeLens Platform - Local-First IndexedDB Persistence Engine
 * Manages sanitized sessions, observations, findings, evidence, snapshots, and reports.
 * Includes asynchronous cursor pagination and automated retention limits.
 */

const DB_NAME = 'scopelens_db';
const DB_VERSION = 1;

export class ScopeLensStorage {
  constructor() {
    this.db = null;
    this.memoryFallback = new Map(); // For non-browser test environments
  }

  /**
   * Initializes or upgrades the IndexedDB database.
   * @returns {Promise<IDBDatabase|null>}
   */
  async init() {
    if (typeof indexedDB === 'undefined') {
      // In-memory mock for headless Node.js unit tests
      return null;
    }

    if (this.db) return this.db;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = event => {
        const db = event.target.result;

        // 1. Sessions store
        if (!db.objectStoreNames.contains('sessions')) {
          const sessions = db.createObjectStore('sessions', { keyPath: 'id' });
          sessions.createIndex('tabId', 'tabId', { unique: false });
          sessions.createIndex('topLevelOrigin', 'topLevelOrigin', { unique: false });
          sessions.createIndex('startedAt', 'startedAt', { unique: false });
        }

        // 2. Observations store
        if (!db.objectStoreNames.contains('observations')) {
          const obs = db.createObjectStore('observations', { keyPath: 'id' });
          obs.createIndex('sessionId', 'sessionId', { unique: false });
          obs.createIndex('origin', 'origin', { unique: false });
          obs.createIndex('kind', 'kind', { unique: false });
          obs.createIndex('observedAt', 'observedAt', { unique: false });
        }

        // 3. Findings store
        if (!db.objectStoreNames.contains('findings')) {
          const findings = db.createObjectStore('findings', { keyPath: 'signature' });
          findings.createIndex('sessionId', 'sessionId', { unique: false });
          findings.createIndex('category', 'category', { unique: false });
          findings.createIndex('severity', 'severity', { unique: false });
        }

        // 4. Evidence store
        if (!db.objectStoreNames.contains('evidence')) {
          const evidence = db.createObjectStore('evidence', { keyPath: 'id' });
          evidence.createIndex('sessionId', 'sessionId', { unique: false });
        }

        // 5. Snapshots store
        if (!db.objectStoreNames.contains('snapshots')) {
          const snapshots = db.createObjectStore('snapshots', { keyPath: 'id' });
          snapshots.createIndex('hostname', 'hostname', { unique: false });
          snapshots.createIndex('createdAt', 'createdAt', { unique: false });
        }

        // 6. Reports store
        if (!db.objectStoreNames.contains('reports')) {
          const reports = db.createObjectStore('reports', { keyPath: 'id' });
          reports.createIndex('generatedAt', 'generatedAt', { unique: false });
        }
      };

      request.onsuccess = event => {
        this.db = event.target.result;
        resolve(this.db);
      };

      request.onerror = event => {
        reject(new Error(`Failed to open IndexedDB: ${event.target.error}`));
      };
    });
  }

  /**
   * Generic put item into an object store.
   * @param {string} storeName
   * @param {Object} item
   * @returns {Promise<void>}
   */
  async put(storeName, item) {
    await this.init();
    if (!this.db) {
      if (!this.memoryFallback.has(storeName)) this.memoryFallback.set(storeName, new Map());
      const key = item.id || item.signature || String(Math.random());
      this.memoryFallback.get(storeName).set(key, item);
      return;
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      const req = store.put(item);
      req.onsuccess = () => resolve();
      req.onerror = e => reject(e.target.error);
    });
  }

  /**
   * Generic get item from an object store by key.
   * @param {string} storeName
   * @param {string} key
   * @returns {Promise<Object|null>}
   */
  async get(storeName, key) {
    await this.init();
    if (!this.db) {
      return this.memoryFallback.get(storeName)?.get(key) || null;
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readonly');
      const store = tx.objectStore(storeName);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = e => reject(e.target.error);
    });
  }

  /**
   * Retrieves all items from an object store, optionally filtered by an index.
   * @param {string} storeName
   * @param {string} [indexName]
   * @param {*} [indexValue]
   * @param {number} [limit=500]
   * @returns {Promise<Array<Object>>}
   */
  async query(storeName, indexName, indexValue, limit = 500) {
    await this.init();
    if (!this.db) {
      const list = Array.from(this.memoryFallback.get(storeName)?.values() || []);
      if (indexName && indexValue !== undefined) {
        return list.filter(item => item[indexName] === indexValue).slice(0, limit);
      }
      return list.slice(0, limit);
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readonly');
      const store = tx.objectStore(storeName);
      const target = indexName ? store.index(indexName) : store;
      const keyRange = indexValue !== undefined ? IDBKeyRange.only(indexValue) : null;
      const req = target.openCursor(keyRange, 'prev');

      const results = [];
      req.onsuccess = e => {
        const cursor = e.target.result;
        if (cursor && results.length < limit) {
          results.push(cursor.value);
          cursor.continue();
        } else {
          resolve(results);
        }
      };
      req.onerror = e => reject(e.target.error);
    });
  }

  /**
   * Convenience alias to get all items from a store.
   * @param {string} storeName
   * @param {number} [limit=1000]
   * @returns {Promise<Array<Object>>}
   */
  async getAll(storeName, limit = 1000) {
    return this.query(storeName, undefined, undefined, limit);
  }

  /**
   * Retrieves items matching an index value.
   * @param {string} storeName
   * @param {string} indexName
   * @param {*} indexValue
   * @param {number} [limit=500]
   * @returns {Promise<Array<Object>>}
   */
  async getByIndex(storeName, indexName, indexValue, limit = 500) {
    return this.query(storeName, indexName, indexValue, limit);
  }

  /**
   * Deletes a single item by key from an object store.
   * @param {string} storeName
   * @param {string} key
   * @returns {Promise<void>}
   */
  async delete(storeName, key) {
    await this.init();
    if (!this.db) {
      this.memoryFallback.get(storeName)?.delete(key);
      return;
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      const req = store.delete(key);
      req.onsuccess = () => resolve();
      req.onerror = e => reject(e.target.error);
    });
  }

  /**
   * Clears a single object store.
   * @param {string} storeName
   * @returns {Promise<void>}
   */
  async clear(storeName) {
    await this.init();
    if (!this.db) {
      this.memoryFallback.get(storeName)?.clear();
      return;
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      const req = store.clear();
      req.onsuccess = () => resolve();
      req.onerror = e => reject(e.target.error);
    });
  }

  /**
   * Enforces retention policy by removing old sessions and orphaned observations.
   * @param {number} [maxSessions=10]
   * @returns {Promise<number>} Number of pruned sessions
   */
  async enforceRetention(maxSessions = 10) {
    await this.init();
    const sessions = await this.query('sessions', 'startedAt', undefined, 100);
    if (sessions.length <= maxSessions) return 0;

    const toDelete = sessions.slice(maxSessions);
    for (const session of toDelete) {
      await this.deleteSession(session.id);
    }
    return toDelete.length;
  }

  /**
   * Deletes a session and its associated observations, findings, and evidence.
   * @param {string} sessionId
   * @returns {Promise<void>}
   */
  async deleteSession(sessionId) {
    await this.init();
    if (!this.db) {
      this.memoryFallback.get('sessions')?.delete(sessionId);
      return;
    }

    const stores = ['sessions', 'observations', 'findings', 'evidence'];
    for (const s of stores) {
      const tx = this.db.transaction(s, 'readwrite');
      const store = tx.objectStore(s);
      if (s === 'sessions') {
        store.delete(sessionId);
      } else {
        const idx = store.index('sessionId');
        const req = idx.openCursor(IDBKeyRange.only(sessionId));
        req.onsuccess = e => {
          const cursor = e.target.result;
          if (cursor) {
            cursor.delete();
            cursor.continue();
          }
        };
      }
    }
  }

  /**
   * Clears all ScopeLens stored data completely.
   * @returns {Promise<void>}
   */
  async clearAll() {
    await this.init();
    if (!this.db) {
      this.memoryFallback.clear();
      return;
    }

    const storeNames = ['sessions', 'observations', 'findings', 'evidence', 'snapshots', 'reports'];
    const tx = this.db.transaction(storeNames, 'readwrite');
    storeNames.forEach(name => tx.objectStore(name).clear());
    return new Promise(resolve => {
      tx.oncomplete = () => resolve();
    });
  }
}

export const localDb = new ScopeLensStorage();
