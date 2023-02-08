package com.goit.app.mvc;

import com.goit.app.note.Note;
import com.goit.app.note.NoteService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;


@RequiredArgsConstructor
@RequestMapping("/note")
@Controller
public class NoteController {
    private final NoteService noteService;

    @GetMapping("/list")
    public ModelAndView getNotes() {
        ModelAndView modelAndView = new ModelAndView("note/note");
        modelAndView.addObject("notes", noteService.listAll());
        return modelAndView;
    }

    @GetMapping("/create")
    public String createNote() {
        return ("note/create-note");
    }

    @PostMapping("/create")
    public RedirectView create(@ModelAttribute Note note) {
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl("/note/list");
        noteService.add(note);
        return redirectView;
    }

    @GetMapping("/delete")
    public RedirectView delete(@RequestParam long id) {
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl("/note/list");
        noteService.deleteById(id);
        return redirectView;
    }

    @GetMapping("/edit")
    public String editNote(Model model,
                           @RequestParam long id) {
        Note note = noteService.getById(id);
        model.addAttribute("note", note);
        return ("note/edit-note");
    }

    @PostMapping("/edit")
    public RedirectView edit(@ModelAttribute Note note) {
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl("/note/list");
        noteService.update(note);
        return redirectView;
    }
}
