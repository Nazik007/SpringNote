package com.goit.app.note;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@RequiredArgsConstructor
@Service
public class NoteService {
    private final NoteRepository noteRepository;

    public List<Note> listAll() {
        return noteRepository.findAll();
    }

    public Note add(Note note) {
        noteRepository.save(note);
        return note;
    }

    public void deleteById(long id) {
        noteRepository.findById(id)
                .stream()
                .findAny()
                .orElseThrow(() -> {
                    throw new NoSuchElementException("The note is missing.");
                });
        noteRepository.deleteById(id);
    }

    public void update(Note note) {
        noteRepository.findById(note.getId())
                .stream()
                .findAny()
                .orElseThrow(() -> {
                    throw new NoSuchElementException("The note is missing.");
                });
        noteRepository.save(note);
    }

    public Note getById(long id) {
        return noteRepository.findById(id)
                .stream()
                .findAny()
                .orElseThrow(() -> {
                    throw new NoSuchElementException("The note is missing.");
                });
    }
}
