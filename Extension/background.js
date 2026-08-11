/**
 * background.js
 *
 * Manifest V3 service worker.
 *
 * Responsibilities:
 * - Store default settings
 * - Capture main-page response headers
 * - Cache HTTP status
 * - Supply response headers to passiveScanner.js
 * - Supply cookies to passiveScanner.js
 */


/* =========================================
   MEMORY HEADER CACHE
========================================= */

const tabHeaderCache = {};


/* =========================================
   SESSION CACHE KEY
========================================= */

function getHeaderCacheKey(tabId) {
  return `header_cache_${tabId}`;
}


/* =========================================
   EXTENSION INSTALL
========================================= */

chrome.runtime.onInstalled.addListener(() => {

  console.log(
    "[AI Vulnerability Scanner] Extension installed."
  );


  chrome.storage.local.get(
    "scanner_settings",
    (data) => {

      if (
        !data.scanner_settings
      ) {

        chrome.storage.local.set({

          scanner_settings: {

            backendUrl:
              "http://127.0.0.1:5000",

            allowActiveScan:
              false,

            theme:
              "dark"

          }

        });
      }

    }
  );
});


/* =========================================
   CAPTURE RESPONSE HEADERS
========================================= */

chrome.webRequest.onHeadersReceived.addListener(

  (details) => {

    /*
     * Only the main website response is
     * stored.
     */

    if (
      details.tabId < 0
    ) {
      return;
    }


    const headers = {};


    (
      details.responseHeaders || []
    ).forEach(
      (header) => {

        if (
          !header?.name
        ) {
          return;
        }


        const name =
          header.name.toLowerCase();


        const value =
          header.value || "";


        /*
         * If a header appears more than once,
         * preserve all values.
         */

        if (
          headers[name]
        ) {

          headers[name] =
            `${headers[name]}, ${value}`;

        } else {

          headers[name] =
            value;
        }

      }
    );


    const headerRecord = {

      url:
        details.url,

      /*
       * Keep both names for compatibility.
       */

      status:
        details.statusCode,

      statusCode:
        details.statusCode,

      headers,

      timestamp:
        Date.now()

    };


    /* Fast in-memory cache */

    tabHeaderCache[
      details.tabId
    ] =
      headerRecord;


    /*
     * Session cache survives service-worker
     * suspension/restart.
     */

    const key =
      getHeaderCacheKey(
        details.tabId
      );


    chrome.storage.session.set({

      [key]:
        headerRecord

    }).catch(
      (error) => {

        console.warn(
          "Could not save header cache:",
          error
        );
      }
    );

  },

  {
    urls: [
      "http://*/*",
      "https://*/*"
    ],

    types: [
      "main_frame"
    ]
  },

  [
    "responseHeaders"
  ]
);


/* =========================================
   MESSAGE ROUTER
========================================= */

chrome.runtime.onMessage.addListener(
  (
    message,
    sender,
    sendResponse
  ) => {


    /* -------------------------------------
       GET RESPONSE HEADERS
    ------------------------------------- */

    if (
      message.type ===
      "GET_CACHED_HEADERS"
    ) {

      const tabId =
        message.tabId;


      /* First try memory */

      const memoryResult =
        tabHeaderCache[
          tabId
        ];


      if (
        memoryResult
      ) {

        sendResponse(
          memoryResult
        );

        return false;
      }


      /*
       * Memory may be empty if the Manifest V3
       * service worker restarted.
       *
       * Try session storage.
       */

      const key =
        getHeaderCacheKey(
          tabId
        );


      chrome.storage.session
        .get(key)
        .then(
          (data) => {

            const record =
              data[key] ||
              null;


            if (
              record
            ) {

              tabHeaderCache[
                tabId
              ] =
                record;
            }


            sendResponse(
              record
            );
          }
        )
        .catch(
          (error) => {

            console.warn(
              "Header cache lookup failed:",
              error
            );

            sendResponse(
              null
            );
          }
        );


      return true;
    }


    /* -------------------------------------
       GET COOKIES
    ------------------------------------- */

    if (
      message.type ===
      "GET_COOKIES_FOR_URL"
    ) {

      if (
        !message.url
      ) {

        sendResponse([]);

        return false;
      }


      chrome.cookies.getAll(
        {
          url:
            message.url
        },

        (cookies) => {

          if (
            chrome.runtime.lastError
          ) {

            console.warn(
              "Cookie lookup failed:",
              chrome.runtime
                .lastError
                .message
            );


            sendResponse([]);

            return;
          }


          sendResponse(
            cookies || []
          );
        }
      );


      /*
       * Keep message channel open because
       * chrome.cookies.getAll is asynchronous.
       */

      return true;
    }


    return false;
  }
);


/* =========================================
   CLEAN CACHE WHEN TAB CLOSES
========================================= */

chrome.tabs.onRemoved.addListener(
  (tabId) => {

    delete tabHeaderCache[
      tabId
    ];


    const key =
      getHeaderCacheKey(
        tabId
      );


    chrome.storage.session
      .remove(key)
      .catch(
        (error) => {

          console.warn(
            "Could not remove header cache:",
            error
          );
        }
      );

  }
);