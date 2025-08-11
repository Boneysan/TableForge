/**
 * Focus management and visible focus states for accessibility
 * Ensures proper focus navigation and keyboard interaction feedback
 */

import { useCallback, useEffect, useRef, useState } from 'react';

interface FocusableElement {
  element: HTMLElement;
  id: string;
  type: 'asset' | 'control' | 'menu' | 'toolbar';
  bounds?: DOMRect;
}

interface UseFocusManagementOptions {
  containerRef: React.RefObject<HTMLElement>;
  onFocusChange?: (focusedId: string | null, element: HTMLElement | null) => void;
  trapFocus?: boolean;
  restoreFocus?: boolean;
}

export function useFocusManagement(options: UseFocusManagementOptions) {
  const { containerRef, onFocusChange, trapFocus = false, restoreFocus = true } = options;

  const [focusedElementId, setFocusedElementId] = useState<string | null>(null);
  const [isKeyboardNavigation, setIsKeyboardNavigation] = useState(false);
  const focusableElementsRef = useRef<FocusableElement[]>([]);
  const lastFocusedElementRef = useRef<HTMLElement | null>(null);
  const focusHistoryRef = useRef<string[]>([]);

  // Update focusable elements list
  const updateFocusableElements = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;

    const focusableSelectors = [
      'button:not([disabled])',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      'a[href]',
      '[tabindex]:not([tabindex="-1"])',
      '[data-focusable="true"]',
    ].join(', ');

    const elements = Array.from(container.querySelectorAll(focusableSelectors));

    focusableElementsRef.current = elements.map((element, index) => ({
      element,
      id: element.getAttribute('data-focus-id') || element.id || `focus-${index}`,
      type: getFocusableElementType(element),
      bounds: element.getBoundingClientRect(),
    }));
  }, [containerRef]);

  // Determine element type for focus management
  const getFocusableElementType = (element: HTMLElement): FocusableElement['type'] => {
    if (element.hasAttribute('data-asset-id')) return 'asset';
    if (element.closest('[role="toolbar"]')) return 'toolbar';
    if (element.closest('[role="menu"]')) return 'menu';
    return 'control';
  };

  // Set focus to specific element by ID
  const setFocusById = useCallback((id: string) => {
    const focusableElement = focusableElementsRef.current.find(item => item.id === id);
    if (focusableElement) {
      focusableElement.element.focus();
      setFocusedElementId(id);

      // Add to focus history
      focusHistoryRef.current = focusHistoryRef.current.filter(historyId => historyId !== id);
      focusHistoryRef.current.push(id);
      if (focusHistoryRef.current.length > 10) {
        focusHistoryRef.current.shift();
      }

      onFocusChange?.(id, focusableElement.element);
    }
  }, [onFocusChange]);

  // Move focus in a direction
  const moveFocus = useCallback((direction: 'next' | 'previous' | 'up' | 'down' | 'left' | 'right') => {
    updateFocusableElements();

    const currentIndex = focusableElementsRef.current.findIndex(item => item.id === focusedElementId);
    let nextIndex = -1;

    switch (direction) {
      case 'next':
        nextIndex = currentIndex + 1;
        if (nextIndex >= focusableElementsRef.current.length) {
          nextIndex = trapFocus ? 0 : currentIndex;
        }
        break;

      case 'previous':
        nextIndex = currentIndex - 1;
        if (nextIndex < 0) {
          nextIndex = trapFocus ? focusableElementsRef.current.length - 1 : currentIndex;
        }
        break;

      case 'up':
      case 'down':
      case 'left':
      case 'right':
        nextIndex = findSpatialFocus(direction, currentIndex);
        break;
    }

    if (nextIndex >= 0 && nextIndex < focusableElementsRef.current.length) {
      const nextElement = focusableElementsRef.current[nextIndex];
      setFocusById(nextElement.id);
    }
  }, [focusedElementId, trapFocus, setFocusById, updateFocusableElements]);

  // Find focus target based on spatial relationships
  const findSpatialFocus = useCallback((direction: 'up' | 'down' | 'left' | 'right', currentIndex: number) => {
    if (currentIndex < 0) return -1;

    const currentElement = focusableElementsRef.current[currentIndex];
    if (!currentElement.bounds) return -1;

    const currentRect = currentElement.bounds;
    let bestCandidate = -1;
    let bestDistance = Infinity;

    focusableElementsRef.current.forEach((candidate, index) => {
      if (index === currentIndex || !candidate.bounds) return;

      const candidateRect = candidate.bounds;
      let isInDirection = false;
      let distance = 0;

      switch (direction) {
        case 'up':
          isInDirection = candidateRect.bottom <= currentRect.top;
          distance = currentRect.top - candidateRect.bottom +
                   Math.abs(candidateRect.left + candidateRect.width / 2 - currentRect.left - currentRect.width / 2);
          break;

        case 'down':
          isInDirection = candidateRect.top >= currentRect.bottom;
          distance = candidateRect.top - currentRect.bottom +
                   Math.abs(candidateRect.left + candidateRect.width / 2 - currentRect.left - currentRect.width / 2);
          break;

        case 'left':
          isInDirection = candidateRect.right <= currentRect.left;
          distance = currentRect.left - candidateRect.right +
                   Math.abs(candidateRect.top + candidateRect.height / 2 - currentRect.top - currentRect.height / 2);
          break;

        case 'right':
          isInDirection = candidateRect.left >= currentRect.right;
          distance = candidateRect.left - currentRect.right +
                   Math.abs(candidateRect.top + candidateRect.height / 2 - currentRect.top - currentRect.height / 2);
          break;
      }

      if (isInDirection && distance < bestDistance) {
        bestDistance = distance;
        bestCandidate = index;
      }
    });

    return bestCandidate;
  }, []);

  // Focus first focusable element
  const focusFirst = useCallback(() => {
    updateFocusableElements();
    if (focusableElementsRef.current.length > 0) {
      setFocusById(focusableElementsRef.current[0].id);
    }
  }, [updateFocusableElements, setFocusById]);

  // Focus last focusable element
  const focusLast = useCallback(() => {
    updateFocusableElements();
    const lastIndex = focusableElementsRef.current.length - 1;
    if (lastIndex >= 0) {
      setFocusById(focusableElementsRef.current[lastIndex].id);
    }
  }, [updateFocusableElements, setFocusById]);

  // Return focus to previous element
  const restorePreviousFocus = useCallback(() => {
    const history = focusHistoryRef.current;
    if (history.length >= 2) {
      // Get second to last (previous) focus
      const previousId = history[history.length - 2];
      setFocusById(previousId);
    } else if (lastFocusedElementRef.current) {
      lastFocusedElementRef.current.focus();
    }
  }, [setFocusById]);

  // Handle focus events
  const handleFocusIn = useCallback((event: FocusEvent) => {
    const target = event.target as HTMLElement;
    const container = containerRef.current;

    if (!container?.contains(target)) return;

    updateFocusableElements();
    const focusableElement = focusableElementsRef.current.find(item => item.element === target);

    if (focusableElement) {
      setFocusedElementId(focusableElement.id);
      onFocusChange?.(focusableElement.id, focusableElement.element);
    }

    // Track keyboard navigation
    if (event.relatedTarget) {
      setIsKeyboardNavigation(true);
    }
  }, [containerRef, updateFocusableElements, onFocusChange]);

  // Handle focus out events
  const handleFocusOut = useCallback((event: FocusEvent) => {
    const target = event.target as HTMLElement;
    const relatedTarget = event.relatedTarget as HTMLElement;
    const container = containerRef.current;

    if (!container) return;

    // If focus is moving outside the container
    if (!relatedTarget || !container.contains(relatedTarget)) {
      if (restoreFocus) {
        lastFocusedElementRef.current = target;
      }
      setFocusedElementId(null);
      onFocusChange?.(null, null);
    }
  }, [containerRef, restoreFocus, onFocusChange]);

  // Handle mouse events to disable keyboard navigation styling
  const handleMouseDown = useCallback(() => {
    setIsKeyboardNavigation(false);
  }, []);

  // Set up event listeners
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    container.addEventListener('focusin', handleFocusIn);
    container.addEventListener('focusout', handleFocusOut);
    container.addEventListener('mousedown', handleMouseDown);

    // Initial update
    updateFocusableElements();

    return () => {
      container.removeEventListener('focusin', handleFocusIn);
      container.removeEventListener('focusout', handleFocusOut);
      container.removeEventListener('mousedown', handleMouseDown);
    };
  }, [containerRef, handleFocusIn, handleFocusOut, handleMouseDown, updateFocusableElements]);

  // Update focusable elements when DOM changes
  useEffect(() => {
    const observer = new MutationObserver(() => {
      updateFocusableElements();
    });

    const container = containerRef.current;
    if (container) {
      observer.observe(container, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['disabled', 'tabindex', 'data-focusable'],
      });
    }

    return () => {
      observer.disconnect();
    };
  }, [containerRef, updateFocusableElements]);

  return {
    focusedElementId,
    isKeyboardNavigation,
    focusableElements: focusableElementsRef.current,
    setFocusById,
    moveFocus,
    focusFirst,
    focusLast,
    restorePreviousFocus,
    updateFocusableElements,
  };
}
